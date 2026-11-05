import fs from 'node:fs';
import os from 'node:os';
import { SkvError, usage } from './errors.mjs';
import { ensurePrivateDir, FILE_MODE } from './fsutil.mjs';
import { isWindows, layout } from './paths.mjs';

export const ACTIONS = ['init', 'set', 'set-file', 'rm', 'import', 'export', 'get', 'run', 'rollback', 'link', 'config', 'passphrase-set', 'passphrase-change', 'passphrase-remove', 'unlock', 'lock'];

/**
 * `agent` when the process runs under a coding agent (CLAUDECODE set by Claude Code, CODEX_* set by Codex),
 * otherwise `user`. ORCA_* is deliberately ignored: Orca exports it in every terminal, including the ones people type in.
 * SKV_ACTOR=user|agent overrides the detection.
 */
export function detectActor(env = process.env) {
  if (env.SKV_ACTOR === 'agent' || env.SKV_ACTOR === 'user') return env.SKV_ACTOR;
  return Object.keys(env).some((k) => k === 'CLAUDECODE' || k.startsWith('CODEX_')) ? 'agent' : 'user';
}

/**
 * Append one audit line. `fields` must never contain secret values: only names, counts, flags and fingerprints.
 * A failure to log never breaks the command (a warning goes to stderr).
 */
export function appendLog(home, fields, env = process.env) {
  if ('value' in fields) throw new Error('audit log entries must not contain values');
  const entry = {
    ts: new Date().toISOString(),
    action: fields.action,
    group: fields.group ?? null,
    key: fields.key ?? null,
    host: os.hostname(),
    actor: detectActor(env),
    user: env.USER || env.USERNAME || safeUser(),
    cwd: process.cwd(),
    ...fields,
  };
  try {
    ensurePrivateDir(home);
    const file = layout(home).log;
    fs.appendFileSync(file, `${JSON.stringify(entry)}\n`, { mode: FILE_MODE });
    if (!isWindows()) fs.chmodSync(file, FILE_MODE);
  } catch (err) {
    process.stderr.write(`skv: warning: could not write the audit log: ${err.message}\n`);
  }
  return entry;
}

function safeUser() {
  try {
    return os.userInfo().username;
  } catch {
    return null;
  }
}

/** "7d", "12h", "30m", "2w" or an ISO date -> Date. */
export function parseSince(spec, now = Date.now()) {
  const m = /^(\d+)([mhdw])$/.exec(String(spec).trim());
  if (m) return new Date(now - Number(m[1]) * { m: 60e3, h: 3600e3, d: 86400e3, w: 604800e3 }[m[2]]);
  const d = new Date(spec);
  if (Number.isNaN(d.getTime())) throw usage(`invalid --since "${spec}": use 30m, 12h, 7d, 2w or a date`);
  return d;
}

export function readLog(home, { group, since } = {}) {
  const file = layout(home).log;
  if (!fs.existsSync(file)) return [];
  const sinceIso = since ? since.toISOString() : null;
  const out = [];
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    let e;
    try {
      e = JSON.parse(line);
    } catch {
      throw new SkvError('parse', `${file} has a malformed line`);
    }
    if (group && e.group !== group && !(e.groups ?? []).includes(group)) continue;
    if (sinceIso && e.ts < sinceIso) continue;
    out.push(e);
  }
  return out;
}
