import fs from 'node:fs';
import { generateKey, parseKey } from './crypto.mjs';
import { SkvError } from './errors.mjs';
import { ensurePrivateDir, writeFileAtomic } from './fsutil.mjs';
import { layout } from './paths.mjs';

/**
 * Key providers: `{ name, available(), load() -> Buffer, store(key) }`.
 * A passphrase (scrypt) or OS keychain provider can be added later without touching the vault format.
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

export function fileKeyProvider(home) {
  const file = layout(home).key;
  return {
    name: 'file',
    describe: file,
    file,
    available: () => fs.existsSync(file),
    load: () => parseKey(fs.readFileSync(file, 'utf8'), file),
    store(key) {
      ensurePrivateDir(home);
      writeFileAtomic(file, `${key.toString('base64')}\n`);
    },
  };
}

/** Providers in priority order: SKV_KEY, then $SKV_HOME/key. */
export const keyProviders = (home, env = process.env) => [envKeyProvider(env), fileKeyProvider(home)];

export function findKeyProvider(home, env = process.env) {
  return keyProviders(home, env).find((p) => p.available()) ?? null;
}

export function loadKey(home, env = process.env) {
  const provider = findKeyProvider(home, env);
  if (!provider) throw new SkvError('no-key', `no master key (SKV_KEY is unset and ${layout(home).key} is missing): run \`skv init\``);
  return provider.load();
}

export { generateKey };
