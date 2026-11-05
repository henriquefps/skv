import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const BIN = path.join(ROOT, 'bin', 'skv.mjs');
export const POSIX = process.platform !== 'win32';

/** A fresh temp folder; SKV_HOME lives inside it, never ~/.skv. */
export function tmpDir() {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'skv-test-')));
}

export function tmpHome() {
  return path.join(tmpDir(), 'skv');
}

/**
 * Run the CLI against `home`. SKV_KEY is cleared so the key file is used unless `env` sets it, and the actor is
 * `user` (the test runner itself may run under an agent) unless `env` sets SKV_ACTOR.
 */
export function skv(home, args, { input = '', env = {}, cwd } = {}) {
  const base = { ...process.env, NO_COLOR: '1', SKV_HOME: home, SKV_ACTOR: 'user' };
  delete base.SKV_KEY;
  return spawnSync(process.execPath, [BIN, ...args], { cwd: cwd ?? path.dirname(home), env: { ...base, ...env }, input, encoding: 'utf8' });
}

export function initHome() {
  const home = tmpHome();
  const r = skv(home, ['init']);
  if (r.status !== 0) throw new Error(r.stderr);
  return home;
}
