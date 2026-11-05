import crypto from 'node:crypto';
import fs from 'node:fs';
import { SkvError } from './errors.mjs';
import { FILE_MODE } from './fsutil.mjs';

export const LOCK_STALE_MS = 30_000;
export const LOCK_TIMEOUT_MS = 5_000;

const sleeper = new Int32Array(new SharedArrayBuffer(4));
const sleep = (ms) => Atomics.wait(sleeper, 0, 0, ms);

const readToken = (file) => {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
};

/**
 * Take an exclusive lock file (created with 'wx'), retrying for up to `timeoutMs`.
 * A lock older than `staleMs` (a crashed process) is removed. Returns a release function.
 */
export function acquireLock(file, { timeoutMs = LOCK_TIMEOUT_MS, staleMs = LOCK_STALE_MS, what = file } = {}) {
  const token = `${process.pid} ${new Date().toISOString()} ${crypto.randomBytes(6).toString('hex')}\n`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const fd = fs.openSync(file, 'wx', FILE_MODE);
      try {
        fs.writeFileSync(fd, token);
      } finally {
        fs.closeSync(fd);
      }
      return () => {
        // Only remove our own lock (it may have been taken over as stale by someone else).
        if (readToken(file) === token) fs.rmSync(file, { force: true });
      };
    } catch (err) {
      // EPERM/EBUSY: Windows reports these while another process is deleting the file.
      if (!['EEXIST', 'EPERM', 'EBUSY'].includes(err.code)) throw err;
    }
    let stat = null;
    try {
      stat = fs.statSync(file);
    } catch {}
    if (stat && Date.now() - stat.mtimeMs > staleMs) {
      const before = readToken(file);
      if (before !== null && readToken(file) === before) fs.rmSync(file, { force: true });
      continue;
    }
    if (Date.now() >= deadline) {
      throw new SkvError(
        'locked',
        `${what} is locked by another skv process (${file}); try again. If no skv is running, the lock goes stale after ${Math.round(staleMs / 1000)}s or can be deleted.`,
      );
    }
    sleep(10 + Math.floor(Math.random() * 40));
  }
}

/** Run `fn` while holding the lock file. */
export function withLock(file, fn, options) {
  const release = acquireLock(file, options);
  try {
    return fn();
  } finally {
    release();
  }
}

export const isLockFile = (name) => name.endsWith('.lock');
