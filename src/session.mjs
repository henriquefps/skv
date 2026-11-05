import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SkvError, usage } from './errors.mjs';
import { isWindows, layout } from './paths.mjs';

/**
 * Unlock sessions (`skv unlock`): a detached background process holds the master key in memory and serves it
 * over a Unix socket (or a Windows named pipe). Every request carries a random token that only lives in
 * $SKV_HOME/session.json (0600), so processes that can't read that file can't use the socket.
 *
 * Protocol: one JSON line per connection, `{ token, op }` with op = status | key | lock; one JSON line back.
 */

export const SERVER_SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'session-server.mjs');
export const DEFAULT_UNLOCK = '8h';
const MAX_SOCKET_PATH = 100; // sun_path is 104 bytes on macOS, 108 on Linux (incl. the NUL)
const MAX_DURATION_MS = 30 * 86400e3;

/** "30s", "30m", "8h", "1d" -> milliseconds (max 30 days). */
export function parseDuration(spec) {
  const m = /^(\d+)([smhd])$/.exec(String(spec ?? '').trim());
  const ms = m ? Number(m[1]) * { s: 1e3, m: 60e3, h: 3600e3, d: 86400e3 }[m[2]] : NaN;
  if (!(ms > 0)) throw usage(`invalid duration "${spec}": use 30m, 8h, 12h, 1d`);
  if (ms > MAX_DURATION_MS) throw usage(`duration "${spec}" is too long (max 30d)`);
  return ms;
}

const homeHash = (home) => crypto.createHash('sha256').update(path.resolve(home)).digest('hex').slice(0, 16);

/**
 * Where the session listens. POSIX: $SKV_HOME/session.sock, or, when that path is too long for a Unix socket,
 * <tmpdir>/skv-<hash of SKV_HOME>/s.sock in a private (0700) folder. Windows: \\.\pipe\skv-<hash>.
 * Returns { socket, dir } where `dir` is the private fallback folder (or null).
 */
export function sessionEndpoint(home, { platform = process.platform, tmpdir = os.tmpdir() } = {}) {
  const hash = homeHash(home);
  if (isWindows(platform)) return { socket: `\\\\.\\pipe\\skv-${hash}`, dir: null };
  const preferred = path.join(home, 'session.sock');
  if (Buffer.byteLength(preferred) <= MAX_SOCKET_PATH) return { socket: preferred, dir: null };
  const dir = path.join(tmpdir, `skv-${hash}`);
  return { socket: path.join(dir, 's.sock'), dir };
}

/** Create (or check) the private fallback folder for the socket: a real folder we own, mode 0700. */
export function ensureSocketDir(dir) {
  try {
    fs.mkdirSync(dir, { mode: 0o700 });
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new SkvError('unsafe-path', `${dir} is not a folder`);
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw new SkvError('unsafe-path', `${dir} belongs to another user`);
  if (st.mode & 0o077) fs.chmodSync(dir, 0o700);
}

/** session.json, or null when missing or unreadable. */
export function readSessionFile(home) {
  try {
    const s = JSON.parse(fs.readFileSync(layout(home).session, 'utf8'));
    return s && typeof s.token === 'string' && typeof s.socket === 'string' ? s : null;
  } catch {
    return null;
  }
}

/** Send one request to a session socket; resolves to the parsed reply. Rejects on connection errors / timeout. */
export function sessionRequest(socket, message, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const conn = net.createConnection(socket);
    let buf = '';
    const timer = setTimeout(() => {
      conn.destroy();
      reject(Object.assign(new Error('session did not answer'), { code: 'ETIMEDOUT' }));
    }, timeoutMs);
    const done = (fn, v) => {
      clearTimeout(timer);
      conn.destroy();
      fn(v);
    };
    conn.setEncoding('utf8');
    conn.on('connect', () => conn.write(`${JSON.stringify(message)}\n`));
    conn.on('data', (d) => {
      buf += d;
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      try {
        done(resolve, JSON.parse(buf.slice(0, nl)));
      } catch (err) {
        done(reject, err);
      }
    });
    conn.on('error', (err) => done(reject, err));
    conn.on('end', () => done(reject, Object.assign(new Error('session closed the connection'), { code: 'ECONNRESET' })));
  });
}

const alive = (pid) => {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
};

/**
 * State of the unlock session:
 *   { state: 'none' }                                  no session.json
 *   { state: 'stale', reason, pid, expiresAt }         session.json left behind (process gone, expired or unreachable)
 *   { state: 'active', pid, expiresAt, key? }          answering; `key` (base64) only when op is 'key'
 */
export async function querySession(home, op = 'status') {
  const s = readSessionFile(home);
  if (!s) return fs.existsSync(layout(home).session) ? { state: 'stale', reason: 'unreadable session.json' } : { state: 'none' };
  const base = { pid: s.pid, expiresAt: s.expiresAt, socket: s.socket };
  if (s.expiresAt && Date.parse(s.expiresAt) <= Date.now()) return { state: 'stale', reason: 'expired', ...base };
  let reply;
  try {
    reply = await sessionRequest(s.socket, { token: s.token, op });
  } catch (err) {
    return { state: 'stale', reason: alive(s.pid) ? `not answering (${err.code ?? err.message})` : 'process gone', ...base };
  }
  if (!reply?.ok) return { state: 'stale', reason: reply?.error ?? 'refused', ...base };
  return { state: 'active', ...base, expiresAt: reply.expiresAt ?? s.expiresAt, ...(reply.key ? { key: reply.key } : {}) };
}

/** Remove the files a dead session left behind (session.json, the socket and its private folder). */
export function removeSessionFiles(home, session = readSessionFile(home)) {
  fs.rmSync(layout(home).session, { force: true });
  const { socket, dir } = sessionEndpoint(home);
  if (!isWindows()) {
    for (const s of new Set([socket, session?.socket].filter(Boolean))) {
      try {
        if (fs.lstatSync(s).isSocket()) fs.rmSync(s, { force: true });
      } catch {}
    }
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Stop the session (if any) and clean up its files. Returns { stopped: bool, stale: bool }. */
export async function stopSession(home) {
  const before = readSessionFile(home);
  const q = await querySession(home);
  if (q.state === 'none') {
    removeSessionFiles(home, null); // a leftover socket without session.json
    return { stopped: false, stale: false };
  }
  if (q.state === 'active') {
    try {
      await sessionRequest(before.socket, { token: before.token, op: 'lock' });
    } catch {}
    for (let i = 0; i < 60 && (fs.existsSync(layout(home).session) || alive(before.pid)); i++) await sleep(50);
  } else if (before && alive(before.pid) && q.reason !== 'expired') {
    // A session process we can't talk to: ask it to stop the hard way.
    try {
      process.kill(before.pid, 'SIGTERM');
    } catch {}
  }
  removeSessionFiles(home, before);
  return { stopped: q.state === 'active', stale: q.state === 'stale' };
}

/**
 * Start a detached session process holding `key` for `ms` milliseconds. Any previous session is stopped first.
 * The key travels to the child over its stdin pipe (never argv or env). Resolves to { pid, expiresAt, socket }.
 */
export async function startSession(home, key, ms) {
  await stopSession(home);
  const { socket, dir } = sessionEndpoint(home);
  if (dir) ensureSocketDir(dir);
  const expiresAt = new Date(Date.now() + ms).toISOString();
  const child = spawn(process.execPath, [SERVER_SCRIPT], { detached: true, stdio: ['pipe', 'ignore', 'ignore'], windowsHide: true });
  let exited = null;
  child.on('exit', (code) => (exited = code ?? -1));
  child.on('error', () => (exited = -1));
  child.stdin.on('error', () => {});
  child.stdin.end(`${JSON.stringify({ home: path.resolve(home), key: key.toString('base64'), expiresAt, socket, dir })}\n`);
  try {
    for (let i = 0; i < 200; i++) {
      if (exited !== null) throw new SkvError('session', `the unlock session could not start (exit ${exited})`);
      const s = readSessionFile(home);
      if (s && s.pid === child.pid) {
        const q = await querySession(home);
        if (q.state === 'active') return { pid: child.pid, expiresAt: q.expiresAt, socket: s.socket };
      }
      await sleep(25);
    }
    try {
      child.kill();
    } catch {}
    throw new SkvError('session', 'the unlock session did not start in time');
  } finally {
    child.unref();
  }
}
