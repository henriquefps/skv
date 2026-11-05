import fs from 'node:fs';
import path from 'node:path';
import { decrypt, encrypt, fingerprint } from './crypto.mjs';
import { SkvError, usage } from './errors.mjs';
import { ensurePrivateDir, writeFileAtomic } from './fsutil.mjs';
import { withLock } from './lock.mjs';
import { layout } from './paths.mjs';

export const HISTORY_LIMIT = 5;
const GROUP_RE = /^[a-z0-9](?:[a-z0-9-]{0,63})$/;
const KEY_RE = /^[A-Z_][A-Z0-9_]*$/;

export const isGroupName = (name) => typeof name === 'string' && name.length <= 64 && GROUP_RE.test(name);
export const isKeyName = (name) => typeof name === 'string' && KEY_RE.test(name);

export function assertGroup(name) {
  if (!isGroupName(name)) throw usage(`invalid group name "${name ?? ''}": lowercase a-z, 0-9 and -, max 64`);
  return name;
}

export function assertKey(name) {
  if (!isKeyName(name)) throw usage(`invalid key name "${name ?? ''}": must match [A-Z_][A-Z0-9_]*`);
  return name;
}

/** "a,b" -> ["a", "b"], validated, no duplicates. */
export function parseGroupList(spec) {
  if (!spec) throw usage('missing group');
  const groups = [...new Set(String(spec).split(',').map((g) => g.trim()).filter(Boolean))];
  if (!groups.length) throw usage('missing group');
  return groups.map(assertGroup);
}

/** A history entry for the current value of `s`. */
function historyEntry(s, now) {
  const old = { value: s.value, replacedAt: now };
  if (s.type !== 'string') old.type = s.type;
  if (s.filename) old.filename = s.filename;
  return old;
}

/** An open vault: a home folder plus its master key. */
export class Vault {
  constructor(home, key) {
    this.home = home;
    this.key = key;
    this.paths = layout(home);
  }

  groupFile(group) {
    return path.join(this.paths.vault, `${assertGroup(group)}.enc`);
  }

  lockFile(group) {
    return path.join(this.paths.vault, `${assertGroup(group)}.lock`);
  }

  /** Run a read-modify-write of one group under its lock file, so concurrent writers don't lose updates. */
  locked(group, fn) {
    ensurePrivateDir(this.paths.vault);
    return withLock(this.lockFile(group), fn, { what: `group "${group}"`, ...this.lockOptions });
  }

  listGroupNames() {
    if (!fs.existsSync(this.paths.vault)) return [];
    return fs
      .readdirSync(this.paths.vault)
      .filter((f) => f.endsWith('.enc'))
      .map((f) => f.slice(0, -4))
      .filter(isGroupName)
      .sort();
  }

  hasGroup(group) {
    return fs.existsSync(this.groupFile(group));
  }

  /** Decrypted group, or null when it does not exist. */
  readGroup(group) {
    const file = this.groupFile(group);
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
    let envelope;
    try {
      envelope = JSON.parse(text);
    } catch {
      throw new SkvError('decrypt', `${file} is not a valid vault file`);
    }
    const data = JSON.parse(decrypt(this.key, envelope, group));
    if (data.group !== group) throw new SkvError('decrypt', `${file} holds group "${data.group}", expected "${group}"`);
    data.secrets ??= {};
    return data;
  }

  requireGroup(group) {
    const data = this.readGroup(group);
    if (!data) throw new SkvError('not-found', `no group "${group}" (see \`skv groups\`)`);
    return data;
  }

  writeGroup(data) {
    ensurePrivateDir(this.paths.vault);
    const envelope = encrypt(this.key, JSON.stringify(data), data.group);
    writeFileAtomic(this.groupFile(data.group), `${JSON.stringify(envelope)}\n`);
  }

  deleteGroup(group) {
    this.locked(group, () => fs.rmSync(this.groupFile(group), { force: true }));
  }

  emptyGroup(group) {
    return { version: 1, group: assertGroup(group), description: '', secrets: {} };
  }

  fingerprint(value) {
    return fingerprint(this.key, value);
  }

  /**
   * Store or replace secrets in one group (one read, one write).
   * `entries`: [{ key, value, type = 'string', filename, note }]. Returns per-key results (never values).
   */
  setSecrets(group, entries, options = {}) {
    return this.locked(group, () => this.#setSecrets(group, entries, options));
  }

  #setSecrets(group, entries, { description } = {}) {
    const data = this.readGroup(group) ?? this.emptyGroup(group);
    if (description !== undefined) data.description = description;
    const now = new Date().toISOString();
    const results = entries.map(({ key, value, type = 'string', filename, note }) => {
      assertKey(key);
      if (typeof value !== 'string') throw new TypeError('secret value must be a string');
      const prev = data.secrets[key];
      const changed = !prev || prev.value !== value || prev.type !== type || (prev.filename ?? null) !== (filename ?? null);
      const status = !prev ? 'added' : changed ? 'changed' : 'unchanged';
      if (!prev) {
        data.secrets[key] = { type, value, createdAt: now, updatedAt: now, history: [] };
      } else if (changed) {
        prev.history = [historyEntry(prev, now), ...(prev.history ?? [])].slice(0, HISTORY_LIMIT);
        Object.assign(prev, { type, value, updatedAt: now });
      }
      const s = data.secrets[key];
      if (type === 'file') s.filename = filename;
      else delete s.filename;
      if (note !== undefined) s.note = note;
      return { key, status, changed, fingerprint: this.fingerprint(value) };
    });
    this.writeGroup(data);
    return results;
  }

  getSecret(group, key) {
    const s = this.requireGroup(group).secrets[assertKey(key)];
    if (!s) throw new SkvError('not-found', `no key ${key} in group "${group}" (see \`skv ls ${group}\`)`);
    return s;
  }

  removeSecret(group, key) {
    assertKey(key);
    this.locked(group, () => {
      const data = this.requireGroup(group);
      if (!data.secrets[key]) throw new SkvError('not-found', `no key ${key} in group "${group}"`);
      delete data.secrets[key];
      this.writeGroup(data);
    });
  }

  /** The value `rollback` would restore: { replacedAt, fingerprint } (never the value), or null without history. */
  previousVersion(group, key) {
    const h = (this.getSecret(group, key).history ?? [])[0];
    return h ? { replacedAt: h.replacedAt, fingerprint: this.fingerprint(h.value) } : null;
  }

  /**
   * Restore the most recent previous value of a key. The current value goes into the history,
   * so a second rollback undoes the first. Returns { key, fingerprint, from, replacedAt } (never values).
   */
  rollback(group, key) {
    assertKey(key);
    return this.locked(group, () => {
      const data = this.requireGroup(group);
      const s = data.secrets[key];
      if (!s) throw new SkvError('not-found', `no key ${key} in group "${group}" (see \`skv ls ${group}\`)`);
      const [prev, ...older] = s.history ?? [];
      if (!prev) throw new SkvError('no-history', `${group}/${key} has no previous value to roll back to`);
      const now = new Date().toISOString();
      const from = this.fingerprint(s.value);
      s.history = [historyEntry(s, now), ...older].slice(0, HISTORY_LIMIT);
      s.type = prev.type ?? 'string';
      s.value = prev.value;
      if (prev.filename) s.filename = prev.filename;
      else delete s.filename;
      s.updatedAt = now;
      this.writeGroup(data);
      return { key, fingerprint: this.fingerprint(s.value), from, replacedAt: prev.replacedAt };
    });
  }

  /** Summary of every group: name, description, count, last change. Never values. */
  groups() {
    return this.listGroupNames().map((name) => {
      const data = this.readGroup(name);
      const secrets = Object.values(data.secrets);
      const updatedAt = secrets.map((s) => s.updatedAt).sort().at(-1) ?? fs.statSync(this.groupFile(name)).mtime.toISOString();
      return { group: name, description: data.description ?? '', count: secrets.length, updatedAt };
    });
  }

  /** Key listing for one group or all: group, key, type, filename, note, createdAt, updatedAt, versions. Never values. */
  list(group) {
    const names = group ? [assertGroup(group)] : this.listGroupNames();
    if (group) this.requireGroup(group);
    return names.flatMap((name) => {
      const data = this.readGroup(name);
      return Object.entries(data.secrets)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, s]) => ({
          group: name,
          key,
          type: s.type,
          ...(s.filename ? { filename: s.filename } : {}),
          note: s.note ?? '',
          createdAt: s.createdAt,
          updatedAt: s.updatedAt,
          history: (s.history ?? []).length,
        }));
    });
  }

  /**
   * Collect the secrets of several groups for run/export: [{ group, key, type, value, filename }].
   * The same key in two groups is an error (which one should win is ambiguous).
   */
  collect(groups) {
    const out = new Map();
    for (const g of groups) {
      for (const [key, s] of Object.entries(this.requireGroup(g).secrets)) {
        if (out.has(key)) throw new SkvError('conflict', `${key} is in both "${out.get(key).group}" and "${g}"`);
        out.set(key, { group: g, key, type: s.type, value: s.value, filename: s.filename });
      }
    }
    return [...out.values()];
  }
}
