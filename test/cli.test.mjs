import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { BIN, initHome, POSIX, skv, tmpDir, tmpHome } from './helpers.mjs';

const SECRET = 'S3cr3t-value-do-not-leak';
const ok = (r) => assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
const hasGit = spawnSync('git', ['--version']).status === 0;

test('commands before init point to skv init', () => {
  const r = skv(tmpHome(), ['ls']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /skv init/);
});

test('usage errors exit 2; no command prints help with exit 2', () => {
  const home = initHome();
  assert.equal(skv(home, []).status, 2);
  assert.equal(skv(home, ['bogus']).status, 2);
  assert.equal(skv(home, ['set', 'g']).status, 2);
  assert.equal(skv(home, ['set', 'BadGroup', 'K'], { input: 'x' }).status, 2);
  assert.equal(skv(home, ['set', 'g', 'lower'], { input: 'x' }).status, 2);
  ok(skv(home, ['--help']));
});

test('set never takes the value from argv', () => {
  const home = initHome();
  const r = skv(home, ['set', 'g', 'K', SECRET]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /stdin/);
  assert.equal(fs.existsSync(path.join(home, 'vault', 'g.enc')), false);
});

test('set via stdin, get, ls, groups, rm', () => {
  const home = initHome();
  const set = skv(home, ['set', 'openai', 'OPENAI_API_KEY', '--note', 'personal', '--desc', 'OpenAI API'], { input: `${SECRET}\n` });
  ok(set);
  assert.match(set.stdout, /added openai\/OPENAI_API_KEY \(fingerprint [0-9a-f]{8}\)/);
  assert.doesNotMatch(set.stdout + set.stderr, new RegExp(SECRET));

  const get = skv(home, ['get', 'openai', 'OPENAI_API_KEY']);
  ok(get);
  assert.equal(get.stdout, SECRET, 'one trailing newline from stdin is stripped; no newline added when piped');

  const ls = skv(home, ['ls', '--json']);
  ok(ls);
  const items = JSON.parse(ls.stdout);
  assert.deepEqual(items.map((i) => [i.group, i.key, i.type, i.note]), [['openai', 'OPENAI_API_KEY', 'string', 'personal']]);
  assert.doesNotMatch(ls.stdout, new RegExp(SECRET));
  assert.doesNotMatch(skv(home, ['ls', 'openai']).stdout, new RegExp(SECRET));

  const groups = JSON.parse(skv(home, ['groups', '--json']).stdout);
  assert.deepEqual(groups.map((g) => [g.group, g.count, g.description]), [['openai', 1, 'OpenAI API']]);

  assert.equal(skv(home, ['rm', 'openai', 'OPENAI_API_KEY']).status, 1, 'needs --yes without a TTY');
  ok(skv(home, ['rm', 'openai', 'OPENAI_API_KEY', '--yes']));
  assert.equal(skv(home, ['get', 'openai', 'OPENAI_API_KEY']).status, 1);
  ok(skv(home, ['rm', 'openai', '--all', '-y']));
  assert.deepEqual(JSON.parse(skv(home, ['groups', '--json']).stdout), []);
});

test('set with empty stdin fails', () => {
  const home = initHome();
  assert.equal(skv(home, ['set', 'g', 'K'], { input: '' }).status, 1);
});

test('SKV_KEY overrides the key file; a wrong key cannot read the vault', () => {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'K'], { input: 'v' }));
  const other = Buffer.alloc(32, 7).toString('base64');
  const r = skv(home, ['get', 'g', 'K'], { env: { SKV_KEY: other } });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /cannot decrypt/);
  const key = fs.readFileSync(path.join(home, 'key'), 'utf8').trim();
  fs.rmSync(path.join(home, 'key'));
  assert.equal(skv(home, ['get', 'g', 'K'], { env: { SKV_KEY: key } }).stdout, 'v');
});

test('set-file stores bytes; get prints them back', () => {
  const home = initHome();
  const src = path.join(tmpDir(), 'upload.jks');
  const bytes = Buffer.from([0, 1, 2, 3, 254, 255, 10, 13]);
  fs.writeFileSync(src, bytes);
  ok(skv(home, ['set-file', 'openlive', 'UPLOAD_JKS', src]));
  const ls = JSON.parse(skv(home, ['ls', 'openlive', '--json']).stdout);
  assert.equal(ls[0].type, 'file');
  assert.equal(ls[0].filename, 'upload.jks');
  const r = spawnSync(process.execPath, [BIN, 'get', 'openlive', 'UPLOAD_JKS'], {
    env: { ...process.env, SKV_HOME: home, SKV_KEY: '', SKV_ACTOR: 'user' },
  });
  assert.deepEqual([...r.stdout], [...bytes]);
});

test('import a dotenv file: added / changed / unchanged', () => {
  const home = initHome();
  const dir = tmpDir();
  const env = path.join(dir, '.env');
  fs.writeFileSync(env, '# comment\nexport A=1\nB="two words"\nC=\'multi\nline\'\n');
  const r1 = skv(home, ['import', 'app', env, '--json']);
  ok(r1);
  assert.deepEqual(JSON.parse(r1.stdout), { group: 'app', added: ['A', 'B', 'C'], changed: [], unchanged: [] });
  fs.writeFileSync(env, 'A=1\nB=changed\nD=new\n');
  const r2 = skv(home, ['import', 'app', env]);
  ok(r2);
  assert.match(r2.stdout, /1 added, 1 changed, 1 unchanged/);
  assert.equal(skv(home, ['get', 'app', 'C']).stdout, 'multi\nline');

  fs.writeFileSync(env, 'lower=1\n');
  const bad = skv(home, ['import', 'app', env]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /lower \(line 1\)/);
});

test('export dotenv/json to stdout and to a 0600 file; round trips through import', () => {
  const home = initHome();
  ok(skv(home, ['set', 'a', 'X'], { input: 'multi\nline "q" $HOME' }));
  ok(skv(home, ['set', 'b', 'Y'], { input: 'plain' }));
  const dotenv = skv(home, ['export', 'a,b']);
  ok(dotenv);
  assert.match(dotenv.stdout, /^X="multi\\nline \\"q\\" \\\$HOME"\nY=plain\n$/);
  const asJson = skv(home, ['export', 'a,b', '--format', 'json']);
  assert.deepEqual(JSON.parse(asJson.stdout), { X: 'multi\nline "q" $HOME', Y: 'plain' });

  const out = path.join(tmpDir(), 'out.env');
  ok(skv(home, ['export', 'a,b', '-o', out]));
  if (POSIX) assert.equal(fs.statSync(out).mode & 0o777, 0o600);
  ok(skv(home, ['import', 'c', out]));
  assert.equal(skv(home, ['get', 'c', 'X']).stdout, 'multi\nline "q" $HOME');
  assert.equal(skv(home, ['export', 'a', '--format', 'yaml']).status, 2);
});

test('export refuses a path inside a git repo unless it is git-ignored', { skip: !hasGit }, () => {
  const home = initHome();
  ok(skv(home, ['set', 'a', 'X'], { input: 'v' }));
  const repo = tmpDir();
  assert.equal(spawnSync('git', ['init', '-q', repo]).status, 0);
  fs.writeFileSync(path.join(repo, '.gitignore'), '.env.local\n');
  const tracked = skv(home, ['export', 'a', '-o', path.join(repo, 'config', '.env')]);
  assert.equal(tracked.status, 1);
  assert.match(tracked.stderr, /not git-ignored/);
  assert.equal(fs.existsSync(path.join(repo, 'config', '.env')), false);
  ok(skv(home, ['export', 'a', '-o', path.join(repo, '.env.local')]));
  assert.equal(fs.readFileSync(path.join(repo, '.env.local'), 'utf8'), 'X=v\n');
});

test('run injects env vars and forwards the exit code', () => {
  const home = initHome();
  ok(skv(home, ['set', 'a', 'X'], { input: SECRET }));
  ok(skv(home, ['set', 'b', 'Y'], { input: 'y' }));
  const r = skv(home, ['run', 'a,b', '--', process.execPath, '-e', `console.log(process.env.X === ${JSON.stringify(SECRET)} && process.env.Y === 'y' ? 'ok' : 'missing')`]);
  ok(r);
  assert.equal(r.stdout.trim(), 'ok');
  assert.equal(skv(home, ['run', 'a', '--', process.execPath, '-e', 'process.exit(7)']).status, 7);
  assert.equal(skv(home, ['run', 'a', '--', 'skv-no-such-command-xyz']).status, 127);
  assert.equal(skv(home, ['run', 'a']).status, 2);
  const unlinked = skv(home, ['run', '--', 'node']);
  assert.equal(unlinked.status, 1, 'no group and no link');
  assert.match(unlinked.stderr, /no groups linked/);
});

test('run: file secrets are a 0600 temp file during the run and gone after', () => {
  const home = initHome();
  const src = path.join(tmpDir(), 'cert.pem');
  fs.writeFileSync(src, 'PEM DATA');
  ok(skv(home, ['set-file', 'f', 'CERT', src]));
  const script = `const fs=require('fs');const p=process.env.CERT;console.log(JSON.stringify({p,body:fs.readFileSync(p,'utf8'),mode:fs.statSync(p).mode&0o777}))`;
  const r = skv(home, ['run', 'f', '--', process.execPath, '-e', script]);
  ok(r);
  const out = JSON.parse(r.stdout);
  assert.equal(out.body, 'PEM DATA');
  assert.ok(out.p.endsWith('cert.pem'));
  if (POSIX) assert.equal(out.mode, 0o600);
  assert.equal(fs.existsSync(out.p), false);
});

test('run: a child killed by a signal is reported', { skip: !POSIX }, () => {
  const home = initHome();
  ok(skv(home, ['set', 'a', 'X'], { input: 'v' }));
  const r = skv(home, ['run', 'a', '--', process.execPath, '-e', "process.kill(process.pid, 'SIGTERM')"]);
  assert.equal(r.signal, 'SIGTERM');
});

test('audit log records actions, actor and fingerprints, never values', () => {
  const home = initHome();
  const agentFree = Object.fromEntries(Object.keys(process.env).filter((k) => k === 'CLAUDECODE' || /^CODEX_/.test(k)).map((k) => [k, undefined]));
  ok(skv(home, ['set', 'g', 'K'], { input: SECRET, env: { ...agentFree, SKV_ACTOR: '', ORCA_TERMINAL_ID: 'x' } }));
  ok(skv(home, ['set', 'g', 'K'], { input: SECRET, env: { CLAUDECODE: '1', SKV_ACTOR: '' } }));
  ok(skv(home, ['get', 'g', 'K']));
  ok(skv(home, ['run', 'g', '--', process.execPath, '-e', '0']));
  ok(skv(home, ['export', 'g']));
  const file = fs.readFileSync(path.join(home, 'log.jsonl'), 'utf8');
  assert.doesNotMatch(file, new RegExp(SECRET));
  const entries = file.trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(entries.map((e) => e.action), ['init', 'set', 'set', 'get', 'run', 'export']);
  const [, s1, s2] = entries;
  assert.equal(s1.actor, 'user');
  assert.equal(s2.actor, 'agent');
  assert.equal(s1.changed, true);
  assert.equal(s2.changed, false);
  assert.match(s1.fingerprint, /^[0-9a-f]{8}$/);
  assert.equal(s1.fingerprint, s2.fingerprint);
  for (const e of entries) for (const f of ['ts', 'action', 'host', 'actor', 'cwd']) assert.ok(f in e, `${f} in ${e.action}`);

  const text = skv(home, ['log', 'g']);
  ok(text);
  assert.doesNotMatch(text.stdout, new RegExp(SECRET));
  assert.equal(JSON.parse(skv(home, ['log', '--json', '--since', '1h']).stdout).length, 6);
  assert.equal(JSON.parse(skv(home, ['log', '--json', '--since', '2999-01-01']).stdout).length, 0);
  assert.equal(skv(home, ['log', '--since', 'soon']).status, 2);
});

test('permissions: home and vault 0700, key/config/groups/log 0600; doctor flags loose modes', { skip: !POSIX }, () => {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'K'], { input: 'v' }));
  const mode = (p) => fs.statSync(path.join(home, p)).mode & 0o777;
  assert.equal(mode('.'), 0o700);
  assert.equal(mode('vault'), 0o700);
  for (const f of ['key', 'config.json', 'vault/g.enc', 'log.jsonl']) assert.equal(mode(f), 0o600, f);
  const good = JSON.parse(skv(home, ['doctor', '--json']).stdout);
  assert.equal(good.ok, true);
  assert.ok(good.results.every((r) => r.level === 'ok'), JSON.stringify(good.results));
  fs.chmodSync(path.join(home, 'key'), 0o644);
  const loose = JSON.parse(skv(home, ['doctor', '--json']).stdout);
  assert.ok(loose.results.some((r) => r.level === 'warn' && /key .* is 644/.test(r.message)));
});

test('doctor reports a tampered group as an error', () => {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'K'], { input: 'v' }));
  const file = path.join(home, 'vault', 'g.enc');
  const env = JSON.parse(fs.readFileSync(file, 'utf8'));
  env.data = Buffer.from('tampered').toString('base64');
  fs.writeFileSync(file, JSON.stringify(env));
  const r = skv(home, ['doctor']);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /error decrypt +g\.enc/);
});

test('detectActor: agent markers only; ORCA_* alone is a user; SKV_ACTOR overrides', async () => {
  const { detectActor } = await import('../src/log.mjs');
  assert.equal(detectActor({ ORCA_TERMINAL_ID: 'x', ORCA_SESSION: 'y' }), 'user');
  assert.equal(detectActor({ CLAUDECODE: '1' }), 'agent');
  assert.equal(detectActor({ CODEX_SANDBOX: 'seatbelt' }), 'agent');
  assert.equal(detectActor({ CLAUDECODE: '1', SKV_ACTOR: 'user' }), 'user');
  assert.equal(detectActor({ SKV_ACTOR: 'agent' }), 'agent');
  assert.equal(detectActor({}), 'user');
});
