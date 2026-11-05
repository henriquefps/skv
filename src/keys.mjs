import fs from 'node:fs';
import { generateKey, parseKey } from './crypto.mjs';
import { SkvError } from './errors.mjs';
import { ensurePrivateDir, writeFileAtomic } from './fsutil.mjs';
import { isWrappedEnvelope, unwrapKey, wrapKey } from './passphrase.mjs';
import { layout } from './paths.mjs';
import { querySession } from './session.mjs';

export const LOCKED_MESSAGE = 'the vault is locked: run `skv unlock`';
export const lockedError = () => new SkvError('locked', LOCKED_MESSAGE);

/**
 * The key file as stored: null when missing, { kind: 'raw', key } for a plain base64 key, or
 * { kind: 'wrapped', envelope } when it is passphrase-protected. Throws 'bad-key' on garbage.
 */
export function readKeyFile(home) {
  const file = layout(home).key;
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  if (text.trim().startsWith('{')) {
    let envelope;
    try {
      envelope = JSON.parse(text);
    } catch {
      throw new SkvError('bad-key', `${file} is not valid JSON`);
    }
    if (!isWrappedEnvelope(envelope)) throw new SkvError('bad-key', `${file} is not a valid passphrase envelope`);
    return { kind: 'wrapped', envelope };
  }
  return { kind: 'raw', key: parseKey(text, file) };
}

/** Write the key file atomically (0600): a raw key, or a passphrase envelope. */
export function writeKeyFile(home, content) {
  ensurePrivateDir(home);
  const file = layout(home).key;
  const text = Buffer.isBuffer(content) ? `${content.toString('base64')}\n` : `${JSON.stringify(content, null, 2)}\n`;
  writeFileAtomic(file, text);
}

/**
 * Key providers: `{ name, describe, available(), load() }`, in priority order.
 * `load()` returns the master key (a Promise for the session provider).
 */
export function envKeyProvider(env = process.env) {
  return {
    name: 'env',
    describe: 'SKV_KEY environment variable',
    available: () => Boolean(env.SKV_KEY),
    load: () => parseKey(env.SKV_KEY, 'SKV_KEY'),
    store() {
      throw new SkvError('read-only', 'the SKV_KEY provider cannot store a key');
    },
  };
}

/** The plain key file. A passphrase-wrapped key file is "available" but loading it without a session is a locked error. */
export function fileKeyProvider(home) {
  const file = layout(home).key;
  return {
    name: 'file',
    describe: file,
    file,
    available: () => fs.existsSync(file),
    load() {
      const k = readKeyFile(home);
      if (!k) throw new SkvError('no-key', `${file} is missing`);
      if (k.kind === 'wrapped') throw lockedError();
      return k.key;
    },
    store: (key) => writeKeyFile(home, key),
  };
}

/** The unlock session (`skv unlock`): holds the key in memory, reached over a local socket / named pipe. */
export function sessionKeyProvider(home) {
  return {
    name: 'session',
    describe: 'unlock session (skv unlock)',
    available: () => fs.existsSync(layout(home).session),
    async load() {
      const s = await querySession(home, 'key');
      if (s.state !== 'active' || !s.key) return null;
      return parseKey(s.key, 'the unlock session');
    },
  };
}

/** Synchronous providers in priority order: SKV_KEY, then $SKV_HOME/key (no session). */
export const keyProviders = (home, env = process.env) => [envKeyProvider(env), fileKeyProvider(home)];

export function findKeyProvider(home, env = process.env) {
  return keyProviders(home, env).find((p) => p.available()) ?? null;
}

const noKey = (home) => new SkvError('no-key', `no master key (SKV_KEY is unset and ${layout(home).key} is missing): run \`skv init\``);

/** Synchronous key lookup without the session: SKV_KEY, then a plain key file. A wrapped key file is a locked error. */
export function loadKey(home, env = process.env) {
  const provider = findKeyProvider(home, env);
  if (!provider) throw noKey(home);
  return provider.load();
}

/**
 * The master key in provider order: SKV_KEY -> unlock session -> plain key file.
 * Returns { key, source }. A wrapped key file without a session is SkvError('locked').
 */
export async function resolveKey(home, env = process.env) {
  const envP = envKeyProvider(env);
  if (envP.available()) return { key: envP.load(), source: 'env' };
  const sessionP = sessionKeyProvider(home);
  if (sessionP.available()) {
    const key = await sessionP.load();
    if (key) return { key, source: 'session' };
  }
  const k = readKeyFile(home);
  if (!k) throw noKey(home);
  if (k.kind === 'wrapped') throw lockedError();
  return { key: k.key, source: 'file' };
}

export { generateKey, unwrapKey, wrapKey };
