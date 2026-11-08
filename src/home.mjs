import fs from 'node:fs';
import path from 'node:path';
import { SkvError } from './errors.mjs';
import { ensurePrivateDir, isTempFile, modeOf, writeFileAtomic } from './fsutil.mjs';
import { envKeyProvider, fileKeyProvider, generateKey, readKeyFile, resolveKey } from './keys.mjs';
import { CONFIG_VERSION, defaultConfig, listLinks } from './links.mjs';
import { isLockFile, LOCK_STALE_MS } from './lock.mjs';
import { isWindows, layout } from './paths.mjs';
import { querySession, sessionEndpoint } from './session.mjs';
import { Vault } from './vault.mjs';

export { CONFIG_VERSION };

/**
 * Create the home folder, vault/, key and config.json. Idempotent: never replaces an existing key or config.
 * Refuses to create a new key when encrypted groups already exist (they would become unreadable).
 */
export function initHome(home, env = process.env) {
  const p = layout(home);
  const created = [];
  ensurePrivateDir(home);
  ensurePrivateDir(p.vault);
  const envP = envKeyProvider(env);
  const existing = readKeyFile(home);
  let keySource;
  if (envP.available()) {
    envP.load();
    keySource = 'env';
  } else if (existing) {
    keySource = existing.kind === 'wrapped' ? 'passphrase' : 'file';
  } else {
    const groups = fs.readdirSync(p.vault).filter((f) => f.endsWith('.enc'));
    if (groups.length) {
      throw new SkvError('no-key', `${p.vault} has ${groups.length} encrypted group(s) but no key: restore ${p.key} or set SKV_KEY instead of creating a new key`);
    }
    fileKeyProvider(home).store(generateKey());
    created.push(p.key);
    keySource = 'file';
  }
  if (!fs.existsSync(p.config)) {
    writeFileAtomic(p.config, `${JSON.stringify(defaultConfig(), null, 2)}\n`);
    created.push(p.config);
  }
  return { home, created, keySource };
}

/**
 * Open the vault for reading/writing: the home must exist and a key must be available
 * (SKV_KEY -> unlock session -> plain key file; a passphrase-protected key file without a session is 'locked').
 */
export async function openVault(home, env = process.env) {
  if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
  const { key, source } = await resolveKey(home, env);
  const vault = new Vault(home, key);
  vault.keySource = source;
  return vault;
}

/**
 * Passphrase and session state, never the key:
 * { keyFile: missing|raw|wrapped|invalid, passphrase: bool, session: {...querySession}, source: env|session|file|locked|none }
 */
export async function keyStatus(home, env = process.env) {
  let keyFile;
  let keyError;
  try {
    const k = readKeyFile(home);
    keyFile = !k ? 'missing' : k.kind;
  } catch (err) {
    keyFile = 'invalid';
    keyError = err.message;
  }
  const session = await querySession(home);
  delete session.key;
  let source;
  if (env.SKV_KEY) source = 'env';
  else if (session.state === 'active') source = 'session';
  else if (keyFile === 'raw') source = 'file';
  else if (keyFile === 'wrapped') source = 'locked';
  else source = 'none';
  return { home, keyFile, ...(keyError ? { keyError } : {}), passphrase: keyFile === 'wrapped', session, source };
}

/** Health checks: [{ level: ok|warn|error, check, message }]. */
export async function doctor(home, env = process.env) {
  const p = layout(home);
  const out = [];
  const add = (level, check, message) => out.push({ level, check, message });
  const win = isWindows();
  const checkMode = (file, want, label) => {
    if (win) return;
    const m = modeOf(file);
    if (m === null) return;
    if (m & 0o077) add('warn', 'permissions', `${label} ${file} is ${m.toString(8)}, expected ${want.toString(8)} (fix: chmod ${want.toString(8)} "${file}")`);
    else add('ok', 'permissions', `${label} ${file} is ${m.toString(8)}`);
  };

  if (!fs.existsSync(home)) {
    add('error', 'home', `${home} does not exist: run \`skv init\``);
    return out;
  }
  add('ok', 'home', home);
  if (win) add('warn', 'permissions', 'Windows: file modes are not enforced; the vault relies on your user profile ACLs');
  checkMode(home, 0o700, 'folder');
  checkMode(p.vault, 0o700, 'folder');

  let key = null;
  const status = await keyStatus(home, env);
  if (status.keyFile === 'invalid') add('error', 'key', status.keyError);
  if (status.keyFile !== 'invalid' || env.SKV_KEY) {
    try {
      const r = await resolveKey(home, env);
      key = r.key;
      const from = { env: 'SKV_KEY environment variable', session: 'the unlock session', file: p.key }[r.source];
      add('ok', 'key', `key from ${from}`);
    } catch (err) {
      if (err.code === 'locked') add('warn', 'key', `${err.message} to check that every group decrypts`);
      else add('error', 'key', err.code === 'no-key' ? `no key: SKV_KEY is unset and ${p.key} is missing` : err.message);
    }
  }
  checkMode(p.key, 0o600, 'key');
  add('ok', 'passphrase', status.passphrase ? 'on: the key file is passphrase-protected (scrypt)' : 'off: the key file holds the raw key');
  const s = status.session;
  if (s.state === 'active') add('ok', 'session', `unlocked until ${s.expiresAt} (pid ${s.pid})`);
  else if (s.state === 'stale') add('warn', 'session', `stale session files (${s.reason}); \`skv lock\` removes them`);
  else add('ok', 'session', status.passphrase ? 'locked (no unlock session)' : 'none');
  if (s.state !== 'none') checkMode(p.session, 0o600, 'session');
  if (!isWindows()) {
    const { socket } = sessionEndpoint(home);
    if (s.state === 'none' && fs.existsSync(socket)) add('warn', 'session', `leftover socket ${socket} without a session (\`skv lock\` removes it)`);
  }

  let configOk = false;
  if (!fs.existsSync(p.config)) add('warn', 'config', `${p.config} is missing (run \`skv init\`)`);
  else {
    try {
      const cfg = JSON.parse(fs.readFileSync(p.config, 'utf8'));
      configOk = true;
      if (cfg.version !== CONFIG_VERSION) add('warn', 'config', `config version ${cfg.version}, expected ${CONFIG_VERSION}`);
      else add('ok', 'config', p.config);
    } catch {
      add('error', 'config', `${p.config} is not valid JSON`);
    }
    checkMode(p.config, 0o600, 'config');
  }

  if (configOk) {
    const links = listLinks(home);
    let bad = 0;
    for (const l of links) {
      if (!l.exists) {
        bad++;
        add('warn', 'links', `${l.path} no longer exists (linked to ${l.groups.join(',')}; remove with \`skv link --rm --path "${l.path}"\`)`);
      }
      const missing = l.groups.filter((g) => {
        if (!fs.existsSync(path.join(p.vault, `${g}.enc`))) return true;
        try {
          return key ? !new Vault(home, key).hasGroup(g) : false;
        } catch {
          return false;
        }
      });
      if (missing.length) {
        bad++;
        add('warn', 'links', `${l.path} is linked to missing group(s) ${missing.join(',')} (re-link with \`skv link\`)`);
      }
    }
    if (!bad) add('ok', 'links', `${links.length} link(s)`);
  }

  if (fs.existsSync(p.vault)) {
    const vault = key ? new Vault(home, key) : null;
    for (const f of fs.readdirSync(p.vault)) {
      const file = path.join(p.vault, f);
      if (isTempFile(f)) {
        add('warn', 'vault', `leftover temp file ${file} (an interrupted write; safe to delete)`);
        continue;
      }
      if (isLockFile(f)) {
        let age = 0;
        try {
          age = Date.now() - fs.statSync(file).mtimeMs;
        } catch {}
        if (age > LOCK_STALE_MS) add('warn', 'vault', `stale lock file ${file} (a crashed write; safe to delete when no skv is running)`);
        continue;
      }
      if (!f.endsWith('.enc')) continue;
      checkMode(file, 0o600, 'group');
      if (!vault) continue;
      try {
        const data = vault.readGroup(f.slice(0, -4));
        const n = Object.keys(data.secrets).length;
        const t = Object.keys(data.tombstones ?? {}).length;
        add('ok', 'decrypt', `${f}: ${n} secret(s)${t ? `, ${t} tombstone(s)` : ''}`);
      } catch (err) {
        add('error', 'decrypt', `${f}: ${err.message}`);
      }
    }
  }
  if (fs.existsSync(p.log)) checkMode(p.log, 0o600, 'log');
  return out;
}
