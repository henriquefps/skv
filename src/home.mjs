import fs from 'node:fs';
import path from 'node:path';
import { SkvError } from './errors.mjs';
import { ensurePrivateDir, isTempFile, modeOf, writeFileAtomic } from './fsutil.mjs';
import { fileKeyProvider, findKeyProvider, generateKey, loadKey } from './keys.mjs';
import { isWindows, layout } from './paths.mjs';
import { Vault } from './vault.mjs';

export const CONFIG_VERSION = 1;

/**
 * Create the home folder, vault/, key and config.json. Idempotent: never replaces an existing key or config.
 * Refuses to create a new key when encrypted groups already exist (they would become unreadable).
 */
export function initHome(home, env = process.env) {
  const p = layout(home);
  const created = [];
  ensurePrivateDir(home);
  ensurePrivateDir(p.vault);
  const provider = findKeyProvider(home, env);
  let keySource;
  if (provider) {
    provider.load();
    keySource = provider.name;
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
    writeFileAtomic(p.config, `${JSON.stringify({ version: CONFIG_VERSION, settings: {}, links: {} }, null, 2)}\n`);
    created.push(p.config);
  }
  return { home, created, keySource };
}

/** Open the vault for reading/writing: the home must exist and a key must be available. */
export function openVault(home, env = process.env) {
  if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
  return new Vault(home, loadKey(home, env));
}

/** Health checks: [{ level: ok|warn|error, check, message }]. */
export function doctor(home, env = process.env) {
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
  const provider = findKeyProvider(home, env);
  if (!provider) add('error', 'key', `no key: SKV_KEY is unset and ${p.key} is missing`);
  else {
    try {
      key = provider.load();
      add('ok', 'key', `key from ${provider.describe}`);
    } catch (err) {
      add('error', 'key', err.message);
    }
  }
  checkMode(p.key, 0o600, 'key');

  if (!fs.existsSync(p.config)) add('warn', 'config', `${p.config} is missing (run \`skv init\`)`);
  else {
    try {
      const cfg = JSON.parse(fs.readFileSync(p.config, 'utf8'));
      if (cfg.version !== CONFIG_VERSION) add('warn', 'config', `config version ${cfg.version}, expected ${CONFIG_VERSION}`);
      else add('ok', 'config', p.config);
    } catch {
      add('error', 'config', `${p.config} is not valid JSON`);
    }
    checkMode(p.config, 0o600, 'config');
  }

  if (fs.existsSync(p.vault)) {
    const vault = key ? new Vault(home, key) : null;
    for (const f of fs.readdirSync(p.vault)) {
      const file = path.join(p.vault, f);
      if (isTempFile(f)) {
        add('warn', 'vault', `leftover temp file ${file} (an interrupted write; safe to delete)`);
        continue;
      }
      if (!f.endsWith('.enc')) continue;
      checkMode(file, 0o600, 'group');
      if (!vault) continue;
      try {
        const n = Object.keys(vault.readGroup(f.slice(0, -4)).secrets).length;
        add('ok', 'decrypt', `${f}: ${n} secret(s)`);
      } catch (err) {
        add('error', 'decrypt', `${f}: ${err.message}`);
      }
    }
  }
  if (fs.existsSync(p.log)) checkMode(p.log, 0o600, 'log');
  return out;
}
