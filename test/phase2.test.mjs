import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { resolveLink, samePath } from '../src/links.mjs';
import { BIN, initHome, skv, tmpDir } from './helpers.mjs';

const SECRET = 'S3cr3t-value-do-not-leak';
const ok = (r) => assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
const readLog = (home) => fs.readFileSync(path.join(home, 'log.jsonl'), 'utf8');
const config = (home) => JSON.parse(fs.readFileSync(path.join(home, 'config.json'), 'utf8'));

test('rollback: needs --yes without a TTY, restores, undoes, logs fingerprints only', () => {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'K'], { input: `${SECRET}-1` }));
  const none = skv(home, ['rollback', 'g', 'K', '--yes']);
  assert.equal(none.status, 1);
  assert.match(none.stderr, /no previous value/);
  ok(skv(home, ['set', 'g', 'K'], { input: `${SECRET}-2` }));

  const noTty = skv(home, ['rollback', 'g', 'K']);
  assert.equal(noTty.status, 1);
  assert.match(noTty.stderr, /--yes/);
  assert.equal(skv(home, ['get', 'g', 'K']).stdout, `${SECRET}-2`);

  const r = skv(home, ['rollback', 'g', 'K', '-y']);
  ok(r);
  assert.match(r.stdout, /rolled back g\/K \(fingerprint [0-9a-f]{8} -> [0-9a-f]{8}/);
  assert.equal(skv(home, ['get', 'g', 'K']).stdout, `${SECRET}-1`);
  ok(skv(home, ['rollback', 'g', 'K', '--yes']));
  assert.equal(skv(home, ['get', 'g', 'K']).stdout, `${SECRET}-2`);

  assert.equal(skv(home, ['rollback', 'g']).status, 2);
  assert.equal(skv(home, ['rollback', 'g', 'NOPE', '--yes']).status, 1);

  const log = readLog(home);
  assert.doesNotMatch(log, new RegExp(SECRET));
  const entries = log.trim().split('\n').map((l) => JSON.parse(l)).filter((e) => e.action === 'rollback');
  assert.equal(entries.length, 2);
  for (const e of entries) {
    assert.match(e.fingerprint, /^[0-9a-f]{8}$/);
    assert.match(e.from, /^[0-9a-f]{8}$/);
  }
  assert.equal(entries[0].fingerprint, entries[1].from);
  assert.match(skv(home, ['log', 'g']).stdout, /rollback/);
});

test('link, links, which, run and export from a subfolder, link --rm', () => {
  const home = initHome();
  ok(skv(home, ['set', 'a', 'X'], { input: SECRET }));
  ok(skv(home, ['set', 'b', 'Y'], { input: 'y' }));
  const project = tmpDir();
  const sub = path.join(project, 'src', 'deep');
  fs.mkdirSync(sub, { recursive: true });

  const missing = skv(home, ['link', 'a,nope', '--path', project]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /no group "nope"/);
  assert.deepEqual(config(home).links, {});
  assert.equal(skv(home, ['link', 'a', '--path', path.join(project, 'not-there')]).status, 1);
  assert.equal(skv(home, ['link']).status, 2);

  ok(skv(home, ['link', 'a,b', '--path', project]));
  assert.deepEqual(config(home).links, { [project]: ['a', 'b'] });

  // relative --path and the default (cwd) resolve to the same absolute folder: replaces, not duplicates
  const relink = skv(home, ['link', 'a,b'], { cwd: project });
  ok(relink);
  assert.match(relink.stdout, /was a,b/);
  assert.deepEqual(Object.keys(config(home).links), [project]);

  const links = JSON.parse(skv(home, ['links', '--json']).stdout);
  assert.deepEqual(links, [{ path: project, groups: ['a', 'b'], exists: true }]);
  assert.match(skv(home, ['links']).stdout, /a,b/);

  const which = JSON.parse(skv(home, ['which', '--json'], { cwd: sub }).stdout);
  assert.deepEqual(which, { dir: sub, linkedAt: project, groups: ['a', 'b'] });
  assert.match(skv(home, ['which', '--path', sub]).stdout, /^a,b/);
  assert.equal(skv(home, ['which', '--path', path.dirname(project)]).status, 1);

  const script = `console.log(process.env.X === ${JSON.stringify(SECRET)} && process.env.Y === 'y' ? 'ok' : 'missing')`;
  const run = skv(home, ['run', '--', process.execPath, '-e', script], { cwd: sub });
  ok(run);
  assert.equal(run.stdout.trim(), 'ok');
  const exp = skv(home, ['export', '--format', 'json'], { cwd: sub });
  ok(exp);
  assert.deepEqual(JSON.parse(exp.stdout), { X: SECRET, Y: 'y' });
  // an explicit group still wins over the link
  assert.deepEqual(JSON.parse(skv(home, ['export', 'b', '--format', 'json'], { cwd: sub }).stdout), { Y: 'y' });

  // a nearer link wins over an ancestor's
  ok(skv(home, ['link', 'b', '--path', path.join(project, 'src')]));
  assert.deepEqual(JSON.parse(skv(home, ['which', '--json'], { cwd: sub }).stdout).groups, ['b']);

  ok(skv(home, ['link', '--rm', '--path', path.join(project, 'src')]));
  assert.equal(skv(home, ['link', '--rm', '--path', path.join(project, 'src')]).status, 1);
  ok(skv(home, ['link', '--rm'], { cwd: project }));
  assert.deepEqual(config(home).links, {});
  const none = skv(home, ['run', '--', process.execPath, '-e', '0'], { cwd: sub });
  assert.equal(none.status, 1);
  assert.match(none.stderr, /no groups linked/);
  assert.equal(skv(home, ['export'], { cwd: sub }).status, 1);

  const log = readLog(home);
  assert.doesNotMatch(log, new RegExp(SECRET));
  assert.ok(log.trim().split('\n').map((l) => JSON.parse(l)).some((e) => e.action === 'link' && e.removed));
});

test('link resolves symlinked folders to the same path', { skip: process.platform === 'win32' }, () => {
  const home = initHome();
  ok(skv(home, ['set', 'a', 'X'], { input: 'v' }));
  const project = tmpDir();
  const alias = path.join(tmpDir(), 'alias');
  fs.symlinkSync(project, alias);
  ok(skv(home, ['link', 'a', '--path', alias]));
  assert.deepEqual(Object.keys(config(home).links), [project]);
  assert.deepEqual(JSON.parse(skv(home, ['which', '--json'], { cwd: project }).stdout).groups, ['a']);
});

test('path matching: case-insensitive on Windows and macOS, nearest ancestor', () => {
  assert.ok(samePath('C:\\Code\\App', 'c:\\code\\app', 'win32'));
  assert.ok(samePath('/Users/me/App', '/users/me/app', 'darwin'));
  assert.equal(samePath('/home/me/App', '/home/me/app', 'linux'), false);
  const links = { 'C:\\Code\\App': ['a'], 'C:\\Code': ['root'] };
  assert.deepEqual(resolveLink(links, 'c:\\code\\app\\src', 'win32'), { path: 'C:\\Code\\App', groups: ['a'] });
  assert.deepEqual(resolveLink(links, 'C:\\Code\\Other', 'win32'), { path: 'C:\\Code', groups: ['root'] });
  assert.equal(resolveLink(links, 'D:\\x', 'win32'), null);
  const posix = { '/home/me/app': ['a'] };
  assert.deepEqual(resolveLink(posix, '/home/me/app/a/b', 'linux').groups, ['a']);
  assert.equal(resolveLink(posix, '/home/me/App/a', 'linux'), null);
  assert.deepEqual(resolveLink(posix, '/home/me/App/a', 'darwin').groups, ['a']);
  assert.equal(resolveLink(posix, '/', 'linux'), null);
});

test('doctor warns about links to missing folders and missing groups', () => {
  const home = initHome();
  ok(skv(home, ['set', 'a', 'X'], { input: 'v' }));
  ok(skv(home, ['set', 'b', 'Y'], { input: 'v' }));
  const gone = tmpDir();
  const kept = tmpDir();
  ok(skv(home, ['link', 'a', '--path', gone]));
  ok(skv(home, ['link', 'b', '--path', kept]));
  const clean = JSON.parse(skv(home, ['doctor', '--json']).stdout);
  assert.ok(clean.results.some((r) => r.check === 'links' && r.level === 'ok'));
  fs.rmSync(gone, { recursive: true });
  ok(skv(home, ['rm', 'b', '--all', '--yes']));
  const r = skv(home, ['doctor', '--json']);
  ok(r);
  const warns = JSON.parse(r.stdout).results.filter((x) => x.check === 'links' && x.level === 'warn');
  assert.equal(warns.length, 2, JSON.stringify(warns));
  assert.ok(warns.some((w) => w.message.includes(gone) && /no longer exists/.test(w.message)));
  assert.ok(warns.some((w) => w.message.includes(kept) && /missing group\(s\) b/.test(w.message)));
  // an orphan link can still be removed
  ok(skv(home, ['link', '--rm', '--path', gone]));
});

test('a stale lock left by a crashed process does not block writes; doctor reports it', () => {
  const home = initHome();
  ok(skv(home, ['set', 'g', 'A'], { input: 'v' }));
  const lock = path.join(home, 'vault', 'g.lock');
  fs.writeFileSync(lock, '99999 crashed\n');
  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(lock, old, old);
  assert.match(skv(home, ['doctor']).stdout, /stale lock file/);
  ok(skv(home, ['set', 'g', 'B'], { input: 'v' }));
  assert.equal(fs.existsSync(lock), false);
});

test('concurrent skv set on the same group from several processes keeps every key', async () => {
  const home = initHome();
  const N = 12;
  const env = { ...process.env, NO_COLOR: '1', SKV_HOME: home };
  delete env.SKV_KEY;
  const runOne = (i) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [BIN, 'set', 'shared', `KEY_${i}`], { env, stdio: ['pipe', 'pipe', 'pipe'] });
      let stderr = '';
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (code) => resolve({ code, stderr }));
      child.stdin.end(`value-${i}`);
    });
  const results = await Promise.all(Array.from({ length: N }, (_, i) => runOne(i)));
  for (const r of results) assert.equal(r.code, 0, r.stderr);
  const keys = JSON.parse(skv(home, ['ls', 'shared', '--json']).stdout).map((s) => s.key).sort();
  assert.deepEqual(keys, Array.from({ length: N }, (_, i) => `KEY_${i}`).sort());
  for (let i = 0; i < N; i++) assert.equal(skv(home, ['get', 'shared', `KEY_${i}`]).stdout, `value-${i}`);
  assert.deepEqual(fs.readdirSync(path.join(home, 'vault')), ['shared.enc']);
});
