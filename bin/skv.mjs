#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { formatDotenv, parseDotenv } from '../src/dotenv.mjs';
import { SkvError, usage } from '../src/errors.mjs';
import { writeFileAtomic } from '../src/fsutil.mjs';
import { assertSafeExportPath } from '../src/git.mjs';
import { doctor, initHome, keyStatus, openVault } from '../src/home.mjs';
import { readKeyFile, writeKeyFile } from '../src/keys.mjs';
import { assertPassphrase, unwrapKey, wrapKey } from '../src/passphrase.mjs';
import { DEFAULT_UNLOCK, parseDuration, startSession, stopSession } from '../src/session.mjs';
import { agentReadDenied, agentReadPolicy, readSettings, SETTINGS, settingFor, writeSetting } from '../src/settings.mjs';
import { linkedGroups, listLinks, normalizeDir, removeLink, setLink } from '../src/links.mjs';
import { appendLog, detectActor, parseSince, readLog } from '../src/log.mjs';
import { skvHome } from '../src/paths.mjs';
import { readPassphrases, readSecretValue } from '../src/prompt.mjs';
import { materialize, runChild } from '../src/run.mjs';
import { assertGroup, assertKey, isKeyName, parseGroupList } from '../src/vault.mjs';

const USAGE = `skv: secrets keeper vault (local, encrypted)

  skv init                                   create $SKV_HOME (default ~/.skv), the key and config; idempotent
  skv groups [--json]                        groups with secret count and last change
  skv ls [group] [--json]                    key names, type, last change; never values
  skv set <group> <KEY> [--note t] [--desc t]   value from stdin (pipe) or a hidden prompt, never argv
  skv set-file <group> <KEY> <path> [--note t]  store a file (binary or text)
  skv get <group> <KEY>                      print one value (logged); file secrets print the file bytes
                                             (refused for agents unless agent-read is allow)
  skv rm <group> <KEY> | skv rm <group> --all   [--yes]
  skv import <group> <file.env>              import a dotenv file (added / changed / unchanged)
  skv rollback <group> <KEY> [--yes]         restore the previous value (run again to undo)
  skv export [group[,group...]] [--format dotenv|json] [-o file]
                                             to a file (0600) or stdout; refuses non-ignored paths in a git repo
  skv run [group[,group...]] -- <cmd> [args...]   run a command with the secrets as env vars
                                             (no group: the groups linked to the current folder)
  skv link <group>[,group...] [--path dir]   link groups to a project folder (default: current folder)
  skv link --rm [--path dir]                 remove a folder's link
  skv links [--json]                         list linked folders
  skv which [--path dir] [--json]            groups that apply to a folder (its link or the nearest linked parent)
  skv log [group] [--since 7d] [--json]      audit log (never values)
  skv doctor [--json]                        permissions, key, files decrypt, orphan links, passphrase, session
  skv config [--json] | skv config set agent-read allow|deny
                                             settings (agent-read: may agents print values; default deny)
  skv passphrase set|change|remove           protect the key file with a passphrase (opt-in; stdin for scripts)
  skv unlock [--for 8h]                      start a background session that holds the key (30m, 12h, 1d...)
  skv lock                                   end the session
  skv status [--json]                        locked / unlocked / no passphrase, expiry, key source

Exit codes: 0 ok, 1 error, 2 usage (run forwards the command's exit code; 127 if it can't be started).
Env: SKV_HOME (vault folder), SKV_KEY (base64 master key, overrides the session and $SKV_HOME/key),
     SKV_ACTOR=user|agent (override agent detection).`;

const FLAGS_WITH_VALUE = new Set(['note', 'desc', 'format', 'output', 'since', 'path', 'for']);
const SHORT = { o: 'output', y: 'yes', h: 'help' };

export function parseArgs(argv) {
  const out = { _: [], flags: {}, rest: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      out.rest = argv.slice(i + 1);
      break;
    }
    let name = null;
    let value;
    if (a.startsWith('--')) [name, value] = a.slice(2).split(/=(.*)/s);
    else if (/^-[a-z]$/.test(a)) name = SHORT[a[1]] ?? a.slice(1);
    if (name === null) {
      out._.push(a);
      continue;
    }
    if (FLAGS_WITH_VALUE.has(name) && value === undefined) {
      if (i + 1 >= argv.length) throw usage(`--${name} needs a value`);
      value = argv[++i];
    }
    out.flags[name] = value ?? true;
  }
  return out;
}

// ---- output --------------------------------------------------------------

const useColor = () => process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { red: paint(31), green: paint(32), yellow: paint(33), dim: paint(2), bold: paint(1) };
const strip = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '');

function table(header, rows) {
  const all = [header.map((h) => c.bold(h)), ...rows.map((r) => r.map(String))];
  const widths = header.map((_, i) => Math.max(...all.map((r) => strip(r[i]).length)));
  return all.map((r) => r.map((cell, i) => (i === r.length - 1 ? cell : cell + ' '.repeat(widths[i] - strip(cell).length))).join('  ').trimEnd()).join('\n');
}

const json = (v) => console.log(JSON.stringify(v, null, 2));
const ago = (iso) => (iso ? iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '-');

async function confirm(question, flags) {
  if (flags.yes) return true;
  if (!process.stdin.isTTY) throw new SkvError('confirm', `${question}\nconfirmation required: re-run with --yes (not a TTY)`);
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    return /^y(es)?$/i.test((await rl.question(`${question} [y/N] `)).trim());
  } finally {
    rl.close();
  }
}

/** --path as a normalized absolute folder (default: the current folder). */
function targetDir(flags) {
  if (flags.path === true) throw usage('--path needs a folder');
  return normalizeDir(flags.path ?? '.');
}

/** Groups from a "a,b" argument, or the ones linked to the current folder when it is absent. */
function groupsOrLinked(home, spec) {
  if (spec) return parseGroupList(spec);
  return linkedGroups(home, normalizeDir('.')).groups.map(assertGroup);
}

function need(pos, n, text) {
  if (pos.length < n) throw usage(`usage: ${text}`);
}

// ---- commands ------------------------------------------------------------

async function main(argv) {
  const { _: pos, flags, rest } = parseArgs(argv);
  const cmd = pos[0];
  if (!cmd || flags.help || cmd === 'help') {
    console.log(USAGE);
    if (!cmd && !flags.help) process.exitCode = 2;
    return;
  }
  const home = skvHome();
  const log = (fields) => appendLog(home, fields);

  switch (cmd) {
    case 'init': {
      const r = initHome(home);
      log({ action: 'init', created: r.created.length > 0 });
      if (!r.created.length) return console.log(`already initialized: ${home} (key from ${r.keySource === 'env' ? 'SKV_KEY' : 'key file'})`);
      console.log(`initialized ${home}`);
      for (const f of r.created) console.log(`  created ${f}`);
      if (r.created.some((f) => f.endsWith(`${path.sep}key`))) {
        console.log(c.yellow('  back up the key file somewhere safe and separate from vault/: without it the vault cannot be decrypted'));
      }
      return;
    }

    case 'groups': {
      const groups = (await openVault(home)).groups();
      if (flags.json) return json(groups);
      if (!groups.length) return console.log('no groups yet (skv set <group> <KEY>)');
      return console.log(table(['GROUP', 'SECRETS', 'UPDATED', 'DESCRIPTION'], groups.map((g) => [g.group, g.count, ago(g.updatedAt), g.description])));
    }

    case 'ls': {
      const group = pos[1] ? assertGroup(pos[1]) : undefined;
      const items = (await openVault(home)).list(group);
      if (flags.json) return json(items);
      if (!items.length) return console.log(group ? `group "${group}" is empty` : 'no secrets yet');
      return console.log(
        table(
          ['GROUP', 'KEY', 'TYPE', 'UPDATED', 'NOTE'],
          items.map((s) => [s.group, s.key, s.type === 'file' ? `file (${s.filename})` : s.type, ago(s.updatedAt), s.note]),
        ),
      );
    }

    case 'set': {
      need(pos, 3, 'skv set <group> <KEY> [--note text]   (value from stdin or a hidden prompt)');
      if (pos.length > 3) throw usage('skv set takes no value argument: pipe it on stdin or type it at the prompt (argv lands in shell history)');
      const [group, key] = [assertGroup(pos[1]), assertKey(pos[2])];
      const vault = await openVault(home);
      const value = await readSecretValue(`${group}/${key}`);
      const [r] = vault.setSecrets(group, [{ key, value, note: str(flags.note) }], { description: str(flags.desc) });
      log({ action: 'set', group, key, changed: r.changed, fingerprint: r.fingerprint });
      return console.log(`${r.status} ${group}/${key} (fingerprint ${r.fingerprint})`);
    }

    case 'set-file': {
      need(pos, 4, 'skv set-file <group> <KEY> <path> [--note text]');
      const [group, key, file] = [assertGroup(pos[1]), assertKey(pos[2]), pos[3]];
      const vault = await openVault(home);
      let bytes;
      try {
        bytes = fs.readFileSync(file);
      } catch (err) {
        throw new SkvError('io', `cannot read ${file}: ${err.code ?? err.message}`);
      }
      const value = bytes.toString('base64');
      const [r] = vault.setSecrets(group, [{ key, value, type: 'file', filename: path.basename(file), note: str(flags.note) }], {
        description: str(flags.desc),
      });
      log({ action: 'set-file', group, key, changed: r.changed, fingerprint: r.fingerprint, bytes: bytes.length });
      return console.log(`${r.status} ${group}/${key} from ${path.basename(file)} (${bytes.length} bytes, fingerprint ${r.fingerprint})`);
    }

    case 'get': {
      need(pos, 3, 'skv get <group> <KEY>');
      const [group, key] = [assertGroup(pos[1]), assertKey(pos[2])];
      if (agentDenied(home)) {
        log({ action: 'get', group, key, denied: true });
        throw agentReadDenied('`skv get`');
      }
      const s = (await openVault(home)).getSecret(group, key);
      log({ action: 'get', group, key });
      if (s.type === 'file') return void process.stdout.write(Buffer.from(s.value, 'base64'));
      return void process.stdout.write(process.stdout.isTTY ? `${s.value}\n` : s.value);
    }

    case 'rm': {
      need(pos, 2, 'skv rm <group> <KEY> | skv rm <group> --all');
      const group = assertGroup(pos[1]);
      const vault = await openVault(home);
      if (flags.all) {
        if (pos[2]) throw usage('skv rm <group> --all takes no key');
        const n = Object.keys(vault.requireGroup(group).secrets).length;
        if (!(await confirm(`delete group "${group}" and its ${n} secret(s)?`, flags))) return console.log('aborted');
        vault.deleteGroup(group);
        log({ action: 'rm', group, all: true, count: n });
        return console.log(`removed group ${group} (${n} secret(s))`);
      }
      need(pos, 3, 'skv rm <group> <KEY> | skv rm <group> --all');
      const key = assertKey(pos[2]);
      vault.getSecret(group, key);
      if (!(await confirm(`delete ${group}/${key}?`, flags))) return console.log('aborted');
      vault.removeSecret(group, key);
      log({ action: 'rm', group, key });
      return console.log(`removed ${group}/${key}`);
    }

    case 'rollback': {
      need(pos, 3, 'skv rollback <group> <KEY> [--yes]');
      if (pos.length > 3) throw usage(`skv rollback: unexpected "${pos[3]}"`);
      const [group, key] = [assertGroup(pos[1]), assertKey(pos[2])];
      const vault = await openVault(home);
      const prev = vault.previousVersion(group, key);
      if (!prev) throw new SkvError('no-history', `${group}/${key} has no previous value to roll back to`);
      if (!(await confirm(`roll back ${group}/${key} to the value replaced at ${ago(prev.replacedAt)} (fingerprint ${prev.fingerprint})?`, flags))) {
        return console.log('aborted');
      }
      const r = vault.rollback(group, key);
      log({ action: 'rollback', group, key, fingerprint: r.fingerprint, from: r.from });
      return console.log(`rolled back ${group}/${key} (fingerprint ${r.from} -> ${r.fingerprint}; run again to undo)`);
    }

    case 'link': {
      const dir = targetDir(flags);
      if (flags.rm) {
        if (pos.length > 1) throw usage('skv link --rm [--path dir] takes no group');
        const r = removeLink(home, dir);
        log({ action: 'link', group: r.groups.join(','), groups: r.groups, path: r.path, removed: true });
        return console.log(`unlinked ${r.path} (was ${r.groups.join(',')})`);
      }
      need(pos, 2, 'skv link <group>[,group...] [--path dir] | skv link --rm [--path dir]');
      if (pos.length > 2) throw usage(`skv link: unexpected "${pos[2]}" (separate groups with commas)`);
      const groups = parseGroupList(pos[1]);
      if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) throw new SkvError('not-found', `${dir} is not a folder`);
      const vault = await openVault(home);
      const missing = groups.filter((g) => !vault.hasGroup(g));
      if (missing.length) throw new SkvError('not-found', `no group ${missing.map((g) => `"${g}"`).join(', ')} (see \`skv groups\`)`);
      const previous = setLink(home, dir, groups);
      log({ action: 'link', group: groups.join(','), groups, path: dir, ...(previous ? { previous } : {}) });
      return console.log(`linked ${dir} -> ${groups.join(',')}${previous ? ` (was ${previous.join(',')})` : ''}`);
    }

    case 'links': {
      if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
      const links = listLinks(home);
      if (flags.json) return json(links);
      if (!links.length) return console.log('no links yet (skv link <group> --path <dir>)');
      return console.log(table(['PATH', 'GROUPS'], links.map((l) => [l.exists ? l.path : `${l.path} ${c.yellow('(missing)')}`, l.groups.join(',')])));
    }

    case 'which': {
      if (pos.length > 1) throw usage('usage: skv which [--path dir] [--json]');
      if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
      const dir = targetDir(flags);
      const link = linkedGroups(home, dir);
      if (flags.json) return json({ dir, linkedAt: link.path, groups: link.groups });
      return console.log(`${link.groups.join(',')}${c.dim(`  (linked at ${link.path})`)}`);
    }

    case 'import': {
      need(pos, 3, 'skv import <group> <file.env>');
      const group = assertGroup(pos[1]);
      let text;
      try {
        text = fs.readFileSync(pos[2], 'utf8');
      } catch (err) {
        throw new SkvError('io', `cannot read ${pos[2]}: ${err.code ?? err.message}`);
      }
      const entries = parseDotenv(text);
      const bad = entries.filter((e) => !isKeyName(e.key));
      if (bad.length) throw new SkvError('invalid', `invalid key name(s) (must match [A-Z_][A-Z0-9_]*): ${bad.map((e) => `${e.key} (line ${e.line})`).join(', ')}`);
      const vault = await openVault(home);
      const last = new Map(entries.map((e) => [e.key, e.value]));
      const results = vault.setSecrets(group, [...last].map(([key, value]) => ({ key, value })), { description: str(flags.desc) });
      for (const r of results) log({ action: 'import', group, key: r.key, changed: r.changed, fingerprint: r.fingerprint, source: path.basename(pos[2]) });
      const by = (st) => results.filter((r) => r.status === st).map((r) => r.key);
      const summary = { group, added: by('added'), changed: by('changed'), unchanged: by('unchanged') };
      if (flags.json) return json(summary);
      console.log(`imported ${results.length} key(s) into ${group}: ${summary.added.length} added, ${summary.changed.length} changed, ${summary.unchanged.length} unchanged`);
      for (const st of ['added', 'changed', 'unchanged']) for (const k of summary[st]) console.log(`  ${st.padEnd(9)} ${k}`);
      return;
    }

    case 'export': {
      if (pos.length > 2) throw usage('usage: skv export [group[,group...]] [--format dotenv|json] [-o file]');
      const groups = groupsOrLinked(home, pos[1]);
      const format = flags.format ?? 'dotenv';
      if (!['dotenv', 'json'].includes(format)) throw usage(`--format must be dotenv or json`);
      const out = flags.output === true ? null : flags.output;
      if (flags.output === true) throw usage('-o needs a file path');
      if (!out && agentDenied(home)) {
        log({ action: 'export', group: groups.join(','), groups, format, target: 'stdout', denied: true });
        throw agentReadDenied('`skv export` to stdout', 'write a git-ignored file with `-o <file>`, or use `skv run <group> -- <cmd>`');
      }
      if (out) assertSafeExportPath(out);
      const secrets = (await openVault(home)).collect(groups);
      const strings = secrets.filter((s) => s.type !== 'file');
      for (const s of secrets) if (s.type === 'file') process.stderr.write(`skv: skipped file secret ${s.group}/${s.key} (use skv get or skv run)\n`);
      const body = format === 'json' ? `${JSON.stringify(Object.fromEntries(strings.map((s) => [s.key, s.value])), null, 2)}\n` : formatDotenv(strings);
      log({ action: 'export', group: groups.join(','), groups, keys: strings.map((s) => s.key), format, target: out ? path.resolve(out) : 'stdout' });
      if (!out) return void process.stdout.write(body);
      writeFileAtomic(path.resolve(out), body);
      return console.error(`wrote ${strings.length} secret(s) to ${path.resolve(out)} (mode 600)`);
    }

    case 'run': {
      if (!rest) throw usage('usage: skv run [group[,group...]] -- <cmd> [args...]');
      if (!rest.length) throw usage('skv run: missing command after --');
      if (pos.length > 2) throw usage(`skv run: unexpected "${pos[2]}" before --`);
      const groups = groupsOrLinked(home, pos[1]);
      const secrets = (await openVault(home)).collect(groups);
      log({ action: 'run', group: groups.join(','), groups, keys: secrets.map((s) => s.key), command: path.basename(rest[0]) });
      const { env, cleanup } = materialize(secrets);
      const r = await runChild(rest[0], rest.slice(1), env, cleanup);
      if (r.error) {
        process.stderr.write(`skv: cannot run ${rest[0]}: ${r.error.code === 'ENOENT' ? 'command not found' : r.error.message}\n`);
        return void (process.exitCode = r.code);
      }
      if (r.signal) {
        const num = os.constants.signals[r.signal] ?? 0;
        if (process.platform !== 'win32') {
          // Die the same way as the child so callers see the signal.
          try {
            process.kill(process.pid, r.signal);
          } catch {}
        }
        return void (process.exitCode = 128 + num);
      }
      return void (process.exitCode = r.code ?? 1);
    }

    case 'log': {
      const group = pos[1] ? assertGroup(pos[1]) : undefined;
      const since = flags.since && flags.since !== true ? parseSince(flags.since) : undefined;
      const entries = readLog(home, { group, since });
      if (flags.json) return json(entries);
      if (!entries.length) return console.log('no log entries');
      return console.log(
        table(
          ['TIME', 'ACTION', 'GROUP', 'KEY', 'ACTOR', 'DETAIL'],
          entries.map((e) => [ago(e.ts), e.action, e.group ?? '-', e.key ?? (e.keys ? `${e.keys.length} key(s)` : '-'), `${e.actor}${e.user ? `:${e.user}` : ''}`, detail(e)]),
        ),
      );
    }

    case 'doctor': {
      const results = await doctor(home);
      const errors = results.filter((r) => r.level === 'error').length;
      if (errors) process.exitCode = 1;
      if (flags.json) return json({ ok: errors === 0, results });
      const mark = { ok: c.green('ok   '), warn: c.yellow('warn '), error: c.red('error') };
      for (const r of results) console.log(`${mark[r.level]} ${r.check.padEnd(11)} ${r.message}`);
      return console.log(errors ? c.red(`\n${errors} error(s)`) : c.green('\nno errors'));
    }

    case 'config': {
      if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
      if (pos[1] === 'set') {
        need(pos, 4, 'skv config set <setting> <value>   (agent-read allow|deny)');
        const [name, value] = [pos[2], pos[3]];
        settingFor(name);
        if (detectActor() === 'agent') throw new SkvError('denied', `only the user can change ${name}: ask them to run \`skv config set ${name} ${value}\``);
        const previous = writeSetting(home, name, value);
        log({ action: 'config', setting: name, setTo: value, previous });
        return console.log(`${name}: ${previous} -> ${value}`);
      }
      if (pos[1]) throw usage('usage: skv config [--json] | skv config set <setting> <value>');
      const settings = readSettings(home);
      if (flags.json) return json(settings);
      return console.log(table(['SETTING', 'VALUE', 'MEANING'], Object.entries(settings).map(([k, v]) => [k, v, SETTINGS[k].describe])));
    }

    case 'passphrase': {
      const sub = pos[1];
      if (!['set', 'change', 'remove'].includes(sub) || pos.length > 2) throw usage('usage: skv passphrase set|change|remove');
      if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
      const k = readKeyFile(home);
      if (!k) throw new SkvError('no-key', `${path.join(home, 'key')} is missing: the passphrase protects the key file (run \`skv init\`)`);
      if (sub === 'set') {
        if (k.kind === 'wrapped') throw new SkvError('exists', 'a passphrase is already set: use `skv passphrase change` or `skv passphrase remove`');
        const [pass] = await readPassphrases([{ label: 'new passphrase', confirm: true }]);
        writeKeyFile(home, wrapKey(k.key, assertPassphrase(pass)));
        k.key.fill(0);
        log({ action: 'passphrase-set' });
        console.log('the key file is now passphrase-protected (the vault itself is unchanged; an SKV_KEY backup still works)');
        return console.log('run `skv unlock` to use the vault; forgetting the passphrase without a backup of the key loses the vault');
      }
      if (k.kind !== 'wrapped') throw new SkvError('no-passphrase', 'no passphrase is set (see `skv passphrase set`)');
      if (sub === 'change') {
        const [cur, next] = await readPassphrases([{ label: 'current passphrase' }, { label: 'new passphrase', confirm: true }]);
        assertPassphrase(next);
        const key = unwrapKey(k.envelope, cur);
        writeKeyFile(home, wrapKey(key, next));
        key.fill(0);
        log({ action: 'passphrase-change' });
        return console.log('passphrase changed (a running unlock session keeps working)');
      }
      const [cur] = await readPassphrases([{ label: 'current passphrase' }]);
      const key = unwrapKey(k.envelope, cur);
      writeKeyFile(home, key);
      key.fill(0);
      await stopSession(home);
      log({ action: 'passphrase-remove' });
      return console.log('passphrase removed: the key file holds the raw key again (mode 600)');
    }

    case 'unlock': {
      if (pos.length > 1) throw usage('usage: skv unlock [--for 8h]');
      if (flags.for === true) throw usage('--for needs a duration (30m, 8h, 1d)');
      const ms = parseDuration(flags.for ?? DEFAULT_UNLOCK);
      if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
      const k = readKeyFile(home);
      if (!k) throw new SkvError('no-key', `${path.join(home, 'key')} is missing: run \`skv init\``);
      if (k.kind !== 'wrapped') throw new SkvError('no-passphrase', 'no passphrase is set, so there is nothing to unlock (see `skv passphrase set`)');
      const [pass] = await readPassphrases([{ label: 'passphrase' }]);
      const key = unwrapKey(k.envelope, pass);
      const r = await startSession(home, key, ms);
      key.fill(0);
      log({ action: 'unlock', expiresAt: r.expiresAt, pid: r.pid });
      return console.log(`unlocked until ${ago(r.expiresAt)} (session pid ${r.pid}; \`skv lock\` ends it)`);
    }

    case 'lock': {
      if (pos.length > 1) throw usage('usage: skv lock');
      const r = await stopSession(home);
      if (r.stopped) log({ action: 'lock' });
      return console.log(r.stopped ? 'locked: the unlock session has ended' : r.stale ? 'no running session (removed stale session files)' : 'no unlock session was running');
    }

    case 'status': {
      if (pos.length > 1) throw usage('usage: skv status [--json]');
      if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
      const st = await keyStatus(home);
      const state = !st.passphrase ? 'no passphrase' : st.session.state === 'active' ? 'unlocked' : 'locked';
      if (flags.json) return json({ state, ...st, agentRead: agentReadPolicy(home) });
      const source = { env: 'SKV_KEY environment variable', session: 'unlock session', file: 'key file', locked: 'none (locked)', none: 'none (no key)' }[st.source];
      console.log(`home:        ${home}`);
      console.log(`state:       ${state}`);
      if (st.session.state === 'active') console.log(`expires:     ${ago(st.session.expiresAt)} (pid ${st.session.pid})`);
      if (st.session.state === 'stale') console.log(`session:     ${c.yellow(`stale (${st.session.reason}); \`skv lock\` cleans up`)}`);
      console.log(`key source:  ${source}`);
      return console.log(`agent-read:  ${agentReadPolicy(home)}`);
    }

    default:
      throw usage(`unknown command: ${cmd}\n\n${USAGE}`);
  }
}

/** True when the caller is an agent and config says agents may not print values. */
const agentDenied = (home) => detectActor() === 'agent' && agentReadPolicy(home) !== 'allow';

const str = (v) => (v === undefined ? undefined : v === true ? '' : String(v));

function detail(e) {
  const parts = [];
  if (e.changed !== undefined) parts.push(e.changed ? 'changed' : 'unchanged');
  if (e.fingerprint) parts.push(`fp ${e.fingerprint}`);
  if (e.command) parts.push(`cmd ${e.command}`);
  if (e.target) parts.push(`-> ${e.target}`);
  if (e.all) parts.push(`whole group (${e.count})`);
  if (e.from) parts.push(`from fp ${e.from}`);
  if (e.path) parts.push(`${e.removed ? 'unlinked' : 'linked'} ${e.path}`);
  if (e.denied) parts.push('DENIED (agent-read)');
  if (e.setting) parts.push(`${e.setting}: ${e.previous} -> ${e.setTo}`);
  if (e.action === 'unlock' && e.expiresAt) parts.push(`until ${e.expiresAt}`);
  return parts.join(', ');
}

main(process.argv.slice(2)).catch((err) => {
  if (err instanceof SkvError) {
    console.error(`skv: ${err.message}`);
    process.exitCode = err.exitCode;
  } else {
    console.error(err);
    process.exitCode = 1;
  }
});
