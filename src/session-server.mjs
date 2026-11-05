#!/usr/bin/env node
/**
 * The unlock session process, started detached by `skv unlock` (src/session.mjs). It reads
 * { home, key, expiresAt, socket, dir } as one JSON line on stdin, keeps the master key only in memory,
 * listens on `socket`, writes $SKV_HOME/session.json (0600) with a random token, and exits on expiry,
 * on `lock`, or on SIGTERM/SIGINT/SIGHUP, removing its files.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import { writeFileAtomic } from './fsutil.mjs';
import { isWindows, layout } from './paths.mjs';

process.title = 'skv-session';
const MAX_LINE = 64 * 1024;
const MAX_TIMER = 2 ** 31 - 1;

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

const cfg = JSON.parse(await readStdin());
const key = Buffer.from(cfg.key, 'base64');
cfg.key = null;
const expiresAtMs = Date.parse(cfg.expiresAt);
const token = crypto.randomBytes(32).toString('base64url');
const tokenDigest = crypto.createHash('sha256').update(token).digest();
const sessionFile = layout(cfg.home).session;
const win = isWindows();
let server;
let timer;
let closing = false;

function tokenOk(candidate) {
  if (typeof candidate !== 'string') return false;
  const d = crypto.createHash('sha256').update(candidate).digest();
  return crypto.timingSafeEqual(d, tokenDigest);
}

function shutdown(code = 0) {
  if (closing) return;
  closing = true;
  clearTimeout(timer);
  key.fill(0);
  try {
    server?.close();
  } catch {}
  try {
    const s = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
    if (s.pid === process.pid) fs.rmSync(sessionFile, { force: true });
  } catch {}
  if (!win) {
    try {
      fs.rmSync(cfg.socket, { force: true });
    } catch {}
    if (cfg.dir) fs.rmSync(cfg.dir, { recursive: true, force: true });
  }
  process.exit(code);
}

function scheduleExpiry() {
  const left = expiresAtMs - Date.now();
  if (left <= 0) return shutdown(0);
  timer = setTimeout(scheduleExpiry, Math.min(left, MAX_TIMER));
}

function handle(conn) {
  conn.setEncoding('utf8');
  conn.setTimeout(5000, () => conn.destroy());
  let buf = '';
  const reply = (obj, after) => conn.end(`${JSON.stringify(obj)}\n`, after);
  conn.on('error', () => {});
  conn.on('data', (d) => {
    buf += d;
    if (buf.length > MAX_LINE) return conn.destroy();
    const nl = buf.indexOf('\n');
    if (nl === -1) return;
    conn.removeAllListeners('data');
    let req;
    try {
      req = JSON.parse(buf.slice(0, nl));
    } catch {
      return reply({ ok: false, error: 'bad request' });
    }
    if (!tokenOk(req?.token)) return reply({ ok: false, error: 'bad token' });
    if (Date.now() >= expiresAtMs) {
      reply({ ok: false, error: 'expired' });
      return shutdown(0);
    }
    const info = { ok: true, pid: process.pid, expiresAt: cfg.expiresAt };
    if (req.op === 'status') return reply(info);
    if (req.op === 'key') return reply({ ...info, key: key.toString('base64') });
    if (req.op === 'lock') return reply(info, () => shutdown(0));
    return reply({ ok: false, error: 'unknown op' });
  });
}

for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
  try {
    process.on(sig, () => shutdown(0));
  } catch {}
}
process.on('uncaughtException', () => shutdown(1));

if (!win) {
  process.umask(0o077); // the socket is created 0600 from the start
  try {
    if (fs.lstatSync(cfg.socket).isSocket()) fs.rmSync(cfg.socket);
  } catch {}
}

server = net.createServer(handle);
server.on('error', () => shutdown(1));
server.listen(cfg.socket, () => {
  if (!win) fs.chmodSync(cfg.socket, 0o600);
  const info = { v: 1, pid: process.pid, socket: cfg.socket, token, startedAt: new Date().toISOString(), expiresAt: cfg.expiresAt };
  writeFileAtomic(sessionFile, `${JSON.stringify(info, null, 2)}\n`);
  scheduleExpiry();
});
