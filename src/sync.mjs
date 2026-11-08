import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { SkvError, usage } from './errors.mjs';
import { assertGroup, assertKey, HISTORY_LIMIT, isKeyName } from './vault.mjs';

/**
 * Machine-to-machine sync over SSH. The local skv spawns `ssh <host> <remote-skv> _sync <op>` and talks to the
 * remote skv with newline-delimited JSON over the pipe. Each machine keeps its own master key: the sender
 * decrypts, the receiver re-encrypts. Values only ever travel through the pipe (never argv, env, logs or disk).
 */
export const PROTOCOL = 1;
export const SSH_OPTIONS = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'];

export const skvVersion = () => JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

export const hello = () => ({ type: 'hello', protocol: PROTOCOL, version: skvVersion() });

export function assertHost(host) {
  if (typeof host !== 'string' || !host) throw usage('missing <host>');
  if (host.startsWith('-')) throw usage(`invalid host "${host}": a host cannot start with "-"`);
  if (/[\s\0]/.test(host)) throw usage(`invalid host "${host}": no whitespace`);
  return host;
}

// ---- merge -----------------------------------------------------------------

const sameValue = (a, b) => a.type === b.type && a.value === b.value && (a.filename ?? null) === (b.filename ?? null);
const sameHistoryEntry = (h, s) => (h.type ?? 'string') === s.type && h.value === s.value && (h.filename ?? null) === (s.filename ?? null);

function historyEntryFor(s, replacedAt) {
  const e = { value: s.value, replacedAt };
  if (s.type !== 'string') e.type = s.type;
  if (s.filename) e.filename = s.filename;
  return e;
}

/** History with `loser` on top, unless an identical value is already in it. Returns the same array when nothing is added. */
function withLoser(history, loser, replacedAt) {
  const h = history ?? [];
  if (h.some((e) => sameHistoryEntry(e, loser))) return h;
  return [historyEntryFor(loser, replacedAt), ...h].slice(0, HISTORY_LIMIT);
}

/** Check a group received over the pipe: names, types, timestamps. Throws a protocol error. */
export function validateIncoming(data, expectedGroup) {
  const bad = (m) => new SkvError('protocol', `malformed group data from the other side: ${m}`);
  if (!data || typeof data !== 'object' || typeof data.group !== 'string') throw bad('no group');
  assertGroup(data.group);
  if (expectedGroup && data.group !== expectedGroup) throw bad(`got "${data.group}", expected "${expectedGroup}"`);
  const secrets = data.secrets ?? {};
  const tombs = data.tombstones ?? {};
  for (const [k, s] of Object.entries(secrets)) {
    if (!isKeyName(k)) throw bad(`key name ${JSON.stringify(k)}`);
    if (!s || typeof s.value !== 'string' || typeof s.updatedAt !== 'string') throw bad(`secret ${k}`);
    if (!['string', 'file'].includes(s.type)) throw bad(`type of ${k}`);
    if (tombs[k]) throw bad(`${k} is both a secret and a tombstone`);
  }
  for (const [k, t] of Object.entries(tombs)) {
    if (!isKeyName(k) || !t || typeof t.deletedAt !== 'string') throw bad(`tombstone ${k}`);
  }
  return { ...data, secrets, tombstones: tombs, description: data.description ?? '' };
}

/**
 * Merge `incoming` (from the sender) into `recv` (the receiver's group, or null). Pure: returns
 * { data, changed, report } and never mutates its arguments. `report` lists key names only:
 * { group, added, updated, deleted, unchanged, conflicts, description }.
 *
 * Per key: only on one side -> copied; same value -> untouched; different value -> newer updatedAt wins and the
 * loser goes into the winner's history; equal timestamps -> the receiver keeps its value (conflict).
 * Tombstone vs value: newer timestamp wins, a tie goes to the deletion.
 */
export function mergeGroup(recv, incoming) {
  const group = incoming.group;
  const out = recv ? structuredClone(recv) : { version: 1, group, description: '', secrets: {} };
  out.secrets ??= {};
  const tombs = (out.tombstones ??= {});
  const inSecrets = incoming.secrets ?? {};
  const inTombs = incoming.tombstones ?? {};
  const report = { group, added: [], updated: [], deleted: [], unchanged: [], conflicts: [], description: false };
  let changed = !recv;

  const keys = [...new Set([...Object.keys(inSecrets), ...Object.keys(inTombs), ...Object.keys(out.secrets), ...Object.keys(tombs)])].sort();
  for (const key of keys) {
    const r = out.secrets[key];
    const rt = tombs[key];
    const i = inSecrets[key];
    const it = inTombs[key];

    if (i) {
      if (!r && !rt) {
        out.secrets[key] = structuredClone(i);
        report.added.push(key);
        changed = true;
      } else if (!r) {
        // incoming value vs receiver tombstone
        if (i.updatedAt > rt.deletedAt) {
          out.secrets[key] = structuredClone(i);
          delete tombs[key];
          report.added.push(key);
          changed = true;
        } else report.unchanged.push(key);
      } else if (sameValue(r, i)) {
        report.unchanged.push(key);
      } else if (i.updatedAt > r.updatedAt) {
        const win = structuredClone(i);
        win.history = withLoser(win.history, r, i.updatedAt);
        out.secrets[key] = win;
        report.updated.push(key);
        changed = true;
      } else if (i.updatedAt < r.updatedAt) {
        const h = withLoser(r.history, i, r.updatedAt);
        if (h !== (r.history ?? [])) {
          r.history = h;
          changed = true;
        }
        report.unchanged.push(key);
      } else {
        report.conflicts.push(key);
      }
    } else if (it) {
      if (r) {
        if (it.deletedAt >= r.updatedAt) {
          delete out.secrets[key];
          tombs[key] = { deletedAt: it.deletedAt };
          report.deleted.push(key);
          changed = true;
        } else report.unchanged.push(key);
      } else if (!rt || it.deletedAt > rt.deletedAt) {
        tombs[key] = { deletedAt: it.deletedAt };
        changed = true; // a tombstone copied silently: nothing visible changed
      }
    } else if (r || rt) {
      report.unchanged.push(key);
    }
  }
  report.unchanged = report.unchanged.filter((k) => out.secrets[k]);
  if (!Object.keys(tombs).length) delete out.tombstones;

  // Group description travels with the newer change; without timestamps a non-empty one fills an empty one.
  const inDesc = incoming.description ?? '';
  if (inDesc !== (out.description ?? '')) {
    const inTs = incoming.descriptionUpdatedAt ?? '';
    const rTs = out.descriptionUpdatedAt ?? '';
    if (inTs > rTs || (inTs === rTs && !out.description && inDesc)) {
      out.description = inDesc;
      if (inTs) out.descriptionUpdatedAt = inTs;
      report.description = true;
      changed = true;
    }
  }

  // A group is "deleted" (hidden) while it has no secrets and either side says so.
  if (Object.keys(out.secrets).length) delete out.deletedAt;
  else {
    const at = [out.deletedAt, incoming.deletedAt].filter(Boolean).sort().at(-1);
    if (at && at !== out.deletedAt) {
      out.deletedAt = at;
      changed = true;
    }
  }
  return { data: out, changed, report };
}

/** Merge into the vault under the group lock; with `dryRun` nothing is written. Returns { report, data }. */
export function applyIncoming(vault, incoming, { dryRun = false } = {}) {
  return vault.locked(incoming.group, () => {
    const { data, changed, report } = mergeGroup(vault.readGroup(incoming.group), incoming);
    if (changed && !dryRun) vault.writeGroup(data);
    return { report, data };
  });
}

export const COUNT_FIELDS = ['added', 'updated', 'deleted', 'unchanged', 'conflicts'];

export function totals(groups) {
  const t = Object.fromEntries(COUNT_FIELDS.map((f) => [f, 0]));
  for (const g of groups) for (const f of COUNT_FIELDS) t[f] += g[f].length;
  return t;
}

/** "group/KEY" names of everything that changed or conflicted, for the audit log. Never values. */
export function changedKeys(groups) {
  return groups.flatMap((g) => ['added', 'updated', 'deleted', 'conflicts'].flatMap((f) => g[f].map((k) => `${g.group}/${k}`)));
}

// ---- wire format -------------------------------------------------------------

export const encodeLine = (msg) => `${JSON.stringify(msg)}\n`;

export function parseLines(text, what) {
  const out = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      throw new SkvError('protocol', `${what} sent something that is not skv sync data`);
    }
  }
  return out;
}

export function parseGroupArg(spec) {
  if (!spec) return null;
  return [...new Set(String(spec).split(',').filter(Boolean))].map(assertGroup);
}

// ---- remote side (the `_sync` subcommand) ---------------------------------------

/** `_sync send`: stream the requested groups (default all, tombstones included). Returns the groups sent. */
export function serveSend(vault, groups, write) {
  // A requested group this machine does not have is skipped: the caller decides whether that is an error.
  const names = (groups ?? vault.listGroupNames()).filter((g) => vault.hasGroupFile(g));
  write(hello());
  const sent = [];
  for (const g of names) {
    const data = vault.readGroup(g);
    write({ type: 'group', data });
    sent.push({ group: g, keys: Object.keys(data.secrets).sort() });
  }
  write({ type: 'end' });
  return sent;
}

/** `_sync receive`: merge the groups on stdin into this vault. Returns { reports, dryRun, peer }. */
export function serveReceive(vault, stdinText, write) {
  const msgs = parseLines(stdinText, 'the sender');
  const head = msgs[0];
  if (!head || head.type !== 'push') throw new SkvError('protocol', 'expected a push header');
  if (head.protocol !== PROTOCOL) throw new SkvError('protocol', `the sender speaks sync protocol ${head.protocol}, this skv speaks ${PROTOCOL}: update skv`);
  const dryRun = head.dryRun === true;
  const reports = [];
  let ended = false;
  for (const m of msgs.slice(1)) {
    if (m.type === 'end') ended = true;
    else if (m.type === 'group') reports.push(applyIncoming(vault, validateIncoming(m.data), { dryRun }).report);
    else throw new SkvError('protocol', `unexpected message "${m.type}"`);
  }
  if (!ended) throw new SkvError('protocol', 'the transfer was cut off before the end: nothing after the last complete group was applied');
  write({ type: 'report', groups: reports });
  return { reports, dryRun, peer: typeof head.from === 'string' ? head.from.slice(0, 100) : null };
}

// ---- local side ---------------------------------------------------------------

/** The ssh executable: SKV_SSH (a .js/.mjs path runs under node, handy for tests) or `ssh`. */
export function sshCommand(env = process.env) {
  const exe = env.SKV_SSH || 'ssh';
  return /\.m?js$/i.test(exe) ? { cmd: process.execPath, pre: [exe] } : { cmd: exe, pre: [] };
}

/**
 * Run `<remoteSkv> _sync <op> [groups]` on `host` over ssh. `input` (a string) goes to stdin.
 * Resolves to { messages, stderr, code } or throws a clear SkvError for ssh/handshake problems.
 */
export function runRemote({ host, remoteSkv = 'skv', op, groups, input, env = process.env }) {
  assertHost(host);
  const remoteCmd = `${remoteSkv} _sync ${op}${groups?.length ? ` ${groups.join(',')}` : ''}`;
  const { cmd, pre } = sshCommand(env);
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, [...pre, ...SSH_OPTIONS, host, remoteCmd], { stdio: ['pipe', 'pipe', 'pipe'], env, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (d) => (stdout += d));
    child.stderr.setEncoding('utf8').on('data', (d) => (stderr += d));
    child.stdin.on('error', () => {}); // the remote may exit before reading everything
    child.on('error', (err) => reject(new SkvError('ssh', `cannot start ${cmd}: ${err.code === 'ENOENT' ? 'not found' : err.message}`)));
    child.on('close', (code) => {
      try {
        resolve(interpret({ host, remoteSkv, stdout, stderr, code }));
      } catch (err) {
        reject(err);
      }
    });
    child.stdin.end(input ?? '');
  });
}

const firstLines = (s, n = 3) => s.trim().split('\n').slice(0, n).join(' | ');

function interpret({ host, remoteSkv, stdout, stderr, code }) {
  let messages = [];
  try {
    messages = parseLines(stdout, host);
  } catch {
    messages = [];
  }
  const err = messages.find((m) => m.type === 'error');
  const hi = messages.find((m) => m.type === 'hello');
  if (err) {
    if (err.code === 'locked') throw new SkvError('locked', `the vault on ${host} is locked: run \`skv unlock\` on ${host}`);
    throw new SkvError(err.code === 'usage' ? 'protocol' : 'remote', `${host}: ${err.message}`);
  }
  if (code === 255) throw new SkvError('ssh', `ssh to ${host} failed: ${firstLines(stderr) || 'no output'}`);
  if (!hi) {
    if (/not found|not recognized|no such file/i.test(stderr)) {
      throw new SkvError('remote', `could not run "${remoteSkv}" on ${host} (${firstLines(stderr, 1)}): install skv there or point to it with --remote-skv "<command>"`);
    }
    throw new SkvError('protocol', `${host} does not support skv sync: update skv on ${host}${stderr.trim() ? ` (${firstLines(stderr, 1)})` : ''}`);
  }
  if (hi.protocol !== PROTOCOL) {
    throw new SkvError('protocol', `${host} speaks sync protocol ${hi.protocol} (skv ${hi.version}), this skv speaks ${PROTOCOL}: update skv on ${host}`);
  }
  if (code !== 0) throw new SkvError('remote', `${host}: skv exited with code ${code}${stderr.trim() ? `: ${firstLines(stderr)}` : ''}`);
  return { messages, stderr, code, version: hi.version };
}

/** Fetch groups from the remote (`_sync send`). Returns the validated groups. */
export async function fetchGroups(opts) {
  const r = await runRemote({ ...opts, op: 'send' });
  const end = r.messages.some((m) => m.type === 'end');
  if (!end) throw new SkvError('protocol', `the transfer from ${opts.host} was cut off before the end: nothing was changed`);
  return r.messages.filter((m) => m.type === 'group').map((m) => validateIncoming(m.data));
}

/** Send groups to the remote (`_sync receive`). Returns the remote's per-group reports. */
export async function sendGroups({ groups: data, dryRun, from, ...opts }) {
  const lines = [{ type: 'push', protocol: PROTOCOL, version: skvVersion(), dryRun: Boolean(dryRun), from }, ...data.map((d) => ({ type: 'group', data: d })), { type: 'end' }];
  const r = await runRemote({ ...opts, op: 'receive', input: lines.map(encodeLine).join('') });
  const rep = r.messages.find((m) => m.type === 'report');
  if (!rep) throw new SkvError('protocol', `${opts.host} did not report back: update skv on ${opts.host}`);
  return rep.groups;
}
