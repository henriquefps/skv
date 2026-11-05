#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { formatDotenv, parseDotenv } from '../src/dotenv.mjs';
import { SkvError, usage } from '../src/errors.mjs';
import { writeFileAtomic } from '../src/fsutil.mjs';
import { assertSafeExportPath } from '../src/git.mjs';
import { doctor, initHome, openVault } from '../src/home.mjs';
import { appendLog, parseSince, readLog } from '../src/log.mjs';
import { skvHome } from '../src/paths.mjs';
import { readSecretValue } from '../src/prompt.mjs';
import { materialize, runChild } from '../src/run.mjs';
import { assertGroup, assertKey, isKeyName, parseGroupList } from '../src/vault.mjs';

const USAGE = `skv: secrets keeper vault (local, encrypted)

  skv init                                   create $SKV_HOME (default ~/.skv), the key and config; idempotent
  skv groups [--json]                        groups with secret count and last change
  skv ls [group] [--json]                    key names, type, last change; never values
  skv set <group> <KEY> [--note t] [--desc t]   value from stdin (pipe) or a hidden prompt, never argv
  skv set-file <group> <KEY> <path> [--note t]  store a file (binary or text)
  skv get <group> <KEY>                      print one value (logged); file secrets print the file bytes
  skv rm <group> <KEY> | skv rm <group> --all   [--yes]
  skv import <group> <file.env>              import a dotenv file (added / changed / unchanged)
  skv export <group>[,group...] [--format dotenv|json] [-o file]
                                             to a file (0600) or stdout; refuses non-ignored paths in a git repo
  skv run <group>[,group...] -- <cmd> [args...]   run a command with the secrets as env vars
  skv log [group] [--since 7d] [--json]      audit log (never values)
  skv doctor [--json]                        permissions, key, files decrypt

Exit codes: 0 ok, 1 error, 2 usage (run forwards the command's exit code; 127 if it can't be started).
Env: SKV_HOME (vault folder), SKV_KEY (base64 master key, overrides $SKV_HOME/key).`;

const FLAGS_WITH_VALUE = new Set(['note', 'desc', 'format', 'output', 'since']);
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
      const groups = openVault(home).groups();
      if (flags.json) return json(groups);
      if (!groups.length) return console.log('no groups yet (skv set <group> <KEY>)');
      return console.log(table(['GROUP', 'SECRETS', 'UPDATED', 'DESCRIPTION'], groups.map((g) => [g.group, g.count, ago(g.updatedAt), g.description])));
    }

    case 'ls': {
      const group = pos[1] ? assertGroup(pos[1]) : undefined;
      const items = openVault(home).list(group);
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
      const vault = openVault(home);
      const value = await readSecretValue(`${group}/${key}`);
      const [r] = vault.setSecrets(group, [{ key, value, note: str(flags.note) }], { description: str(flags.desc) });
      log({ action: 'set', group, key, changed: r.changed, fingerprint: r.fingerprint });
      return console.log(`${r.status} ${group}/${key} (fingerprint ${r.fingerprint})`);
    }

    case 'set-file': {
      need(pos, 4, 'skv set-file <group> <KEY> <path> [--note text]');
      const [group, key, file] = [assertGroup(pos[1]), assertKey(pos[2]), pos[3]];
      const vault = openVault(home);
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
      const s = openVault(home).getSecret(group, key);
      log({ action: 'get', group, key });
      if (s.type === 'file') return void process.stdout.write(Buffer.from(s.value, 'base64'));
      return void process.stdout.write(process.stdout.isTTY ? `${s.value}\n` : s.value);
    }

    case 'rm': {
      need(pos, 2, 'skv rm <group> <KEY> | skv rm <group> --all');
      const group = assertGroup(pos[1]);
      const vault = openVault(home);
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
      const vault = openVault(home);
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
      need(pos, 2, 'skv export <group>[,group...] [--format dotenv|json] [-o file]');
      const groups = parseGroupList(pos[1]);
      const format = flags.format ?? 'dotenv';
      if (!['dotenv', 'json'].includes(format)) throw usage(`--format must be dotenv or json`);
      const out = flags.output === true ? null : flags.output;
      if (flags.output === true) throw usage('-o needs a file path');
      if (out) assertSafeExportPath(out);
      const secrets = openVault(home).collect(groups);
      const strings = secrets.filter((s) => s.type !== 'file');
      for (const s of secrets) if (s.type === 'file') process.stderr.write(`skv: skipped file secret ${s.group}/${s.key} (use skv get or skv run)\n`);
      const body = format === 'json' ? `${JSON.stringify(Object.fromEntries(strings.map((s) => [s.key, s.value])), null, 2)}\n` : formatDotenv(strings);
      log({ action: 'export', group: groups.join(','), groups, keys: strings.map((s) => s.key), format, target: out ? path.resolve(out) : 'stdout' });
      if (!out) return void process.stdout.write(body);
      writeFileAtomic(path.resolve(out), body);
      return console.error(`wrote ${strings.length} secret(s) to ${path.resolve(out)} (mode 600)`);
    }

    case 'run': {
      if (!rest) throw usage('usage: skv run <group>[,group...] -- <cmd> [args...]');
      if (!rest.length) throw usage('skv run: missing command after --');
      if (pos.length < 2) throw usage('skv run: missing group (linking groups to a folder comes in a later version)');
      if (pos.length > 2) throw usage(`skv run: unexpected "${pos[2]}" before --`);
      const groups = parseGroupList(pos[1]);
      const secrets = openVault(home).collect(groups);
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
      const results = doctor(home);
      const errors = results.filter((r) => r.level === 'error').length;
      if (errors) process.exitCode = 1;
      if (flags.json) return json({ ok: errors === 0, results });
      const mark = { ok: c.green('ok   '), warn: c.yellow('warn '), error: c.red('error') };
      for (const r of results) console.log(`${mark[r.level]} ${r.check.padEnd(11)} ${r.message}`);
      return console.log(errors ? c.red(`\n${errors} error(s)`) : c.green('\nno errors'));
    }

    default:
      throw usage(`unknown command: ${cmd}\n\n${USAGE}`);
  }
}

const str = (v) => (v === undefined ? undefined : v === true ? '' : String(v));

function detail(e) {
  const parts = [];
  if (e.changed !== undefined) parts.push(e.changed ? 'changed' : 'unchanged');
  if (e.fingerprint) parts.push(`fp ${e.fingerprint}`);
  if (e.command) parts.push(`cmd ${e.command}`);
  if (e.target) parts.push(`-> ${e.target}`);
  if (e.all) parts.push(`whole group (${e.count})`);
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
