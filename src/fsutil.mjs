import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isWindows } from './paths.mjs';

export const DIR_MODE = 0o700;
export const FILE_MODE = 0o600;

/** Create a folder (and parents) and make it 0700. On Windows modes are best effort (ignored by the OS). */
export function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  if (!isWindows()) fs.chmodSync(dir, DIR_MODE);
}

/** Atomic write: temp file in the same folder (0600), fsync, rename over the target. */
export function writeFileAtomic(file, data, mode = FILE_MODE) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  const fd = fs.openSync(tmp, 'wx', mode);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (!isWindows()) fs.chmodSync(tmp, mode);
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

/** Permission bits of a path, or null when missing. */
export function modeOf(p) {
  try {
    return fs.statSync(p).mode & 0o777;
  } catch {
    return null;
  }
}

export const isTempFile = (name) => /^\..+\.tmp-\d+-[0-9a-f]+$/.test(name);
