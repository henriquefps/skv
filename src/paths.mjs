import os from 'node:os';
import path from 'node:path';

/** Root folder: $SKV_HOME, default ~/.skv. */
export function skvHome(env = process.env) {
  return path.resolve(env.SKV_HOME || path.join(os.homedir(), '.skv'));
}

export function layout(home) {
  return {
    home,
    key: path.join(home, 'key'),
    config: path.join(home, 'config.json'),
    vault: path.join(home, 'vault'),
    log: path.join(home, 'log.jsonl'),
  };
}

export const isWindows = (platform = process.platform) => platform === 'win32';
