import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { openVault } from '../src/home.mjs';
import { mergeGroup } from '../src/sync.mjs';
import { initHome, skv, tmpDir } from './helpers.mjs';

const FAKE_SSH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fake-ssh.mjs');
const V1 = 'S3cr3t-sync-value-one';
const V2 = 'S3cr3t-sync-value-two';
const V3 = 'S3cr3t-sync-value-three';
const ok = (r) => assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const logEntries = (home) => fs.readFileSync(path.join(home, 'log.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));

/** Two machines: A (local) and B (remote, reached through the fake ssh). */
function machines() {
  const a = initHome();
  const b = initHome();
  const logFile = path.join(tmpDir(), 'ssh.log');
  const env = { SKV_SSH: FAKE_SSH, SKV_FAKE_REMOTE_HOME: b, SKV_FAKE_LOG: logFile };
  const run = (args, opts = {}) => skv(a, args, { ...opts, env: { ...env, ...opts.env } });
  const onB = (args, opts) => skv(b, args, opts);
  const set = (home, g, k, v, extra = []) => ok(skv(home, ['set', g, k, ...extra], { input: v }));
  const value = (home, g, k) => skv(home, ['get', g, k]).stdout;
  return { a, b, run, onB, set, value, logFile, env };
}

test('push to an empty remote copies everything, values readable on the remote with its own key', () => {
  const m = machines();
  m.set(m.a, 'openai', 'OPENAI_API_KEY', V1, ['--note', 'personal', '--desc', 'OpenAI']);
  m.set(m.a, 'other', 'TOKEN', V2);
  const r = m.run(['push', 'my-server']);
  ok(r);
  assert.match(r.stdout, /3? ?2 added|2 added/);
  assert.equal(m.value(m.b, 'openai', 'OPENAI_API_KEY'), V1);
  assert.equal(m.value(m.b, 'other', 'TOKEN'), V2);
  const listed = JSON.parse(m.onB(['ls', 'openai', '--json']).stdout);
  assert.equal(listed[0].note, 'personal');
  assert.equal(JSON.parse(m.onB(['groups', '--json']).stdout).find((g) => g.group === 'openai').description, 'OpenAI');
  assert.notEqual(fs.readFileSync(path.join(m.a, 'key'), 'utf8'), fs.readFileSync(path.join(m.b, 'key'), 'utf8'), 'each machine has its own key');
  // second push: nothing changes, updatedAt untouched
  const before = fs.readFileSync(path.join(m.b, 'vault', 'openai.enc'), 'utf8');
  const again = JSON.parse(m.run(['push', 'my-server', '--json']).stdout);
  assert.deepEqual(again.remote.totals, { added: 0, updated: 0, deleted: 0, unchanged: 2, conflicts: 0 });
  assert.equal(fs.readFileSync(path.join(m.b, 'vault', 'openai.enc'), 'utf8'), before);
});

test('pull fetches the remote into the local vault', () => {
  const m = machines();
  m.set(m.b, 'g', 'KEY1', V1);
  const r = m.run(['pull', 'my-server']);
  ok(r);
  assert.match(r.stdout, /1 added/);
  assert.equal(m.value(m.a, 'g', 'KEY1'), V1);
  assert.equal(m.run(['pull', 'my-server', 'nope']).status, 1, 'a group the remote does not have');
});

test('sync merges in both directions', () => {
  const m = machines();
  m.set(m.a, 'g', 'ONLY_A', V1);
  m.set(m.b, 'g', 'ONLY_B', V2);
  m.set(m.b, 'h', 'ALSO_B', V3);
  ok(m.run(['sync', 'my-server']));
  for (const home of [m.a, m.b]) {
    assert.equal(m.value(home, 'g', 'ONLY_A'), V1);
    assert.equal(m.value(home, 'g', 'ONLY_B'), V2);
    assert.equal(m.value(home, 'h', 'ALSO_B'), V3);
  }
  const again = JSON.parse(m.run(['sync', 'my-server', '--json']).stdout);
  assert.equal(again.local.totals.added + again.local.totals.updated + again.remote.totals.added + again.remote.totals.updated, 0);
});

test('newer wins, the loser goes into the history and rollback undoes it', async () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  ok(m.run(['push', 'my-server']));
  await sleep(15);
  m.set(m.a, 'g', 'K', V2); // newer on A
  const r = JSON.parse(m.run(['push', 'my-server', '--json']).stdout);
  assert.deepEqual(r.remote.groups[0].updated, ['K']);
  assert.equal(m.value(m.b, 'g', 'K'), V2);
  ok(m.onB(['rollback', 'g', 'K', '--yes']));
  assert.equal(m.value(m.b, 'g', 'K'), V1, 'the replaced value is in the history');
  // B is now newer than A: a push from A must not overwrite it, a pull brings it to A
  await sleep(15);
  ok(m.onB(['rollback', 'g', 'K', '--yes'])); // back to V2, newest on B
  m.set(m.b, 'g', 'K', V3);
  const push = JSON.parse(m.run(['push', 'my-server', '--json']).stdout);
  assert.equal(push.remote.totals.updated, 0);
  assert.equal(m.value(m.b, 'g', 'K'), V3);
  ok(m.run(['pull', 'my-server']));
  assert.equal(m.value(m.a, 'g', 'K'), V3);
  ok(m.run(['rollback', 'g', 'K', '--yes']));
  assert.equal(m.value(m.a, 'g', 'K'), V2, 'the local loser is in the local history');
});

test('equal values are untouched; a tie with different values keeps the receiver value and reports a conflict', () => {
  const base = { version: 1, group: 'g', description: '', secrets: {} };
  const e = (value, updatedAt) => ({ type: 'string', value, createdAt: updatedAt, updatedAt, history: [] });
  const same = mergeGroup({ ...base, secrets: { K: e('x', '2026-01-01T00:00:00.000Z') } }, { ...base, secrets: { K: e('x', '2026-02-01T00:00:00.000Z') } });
  assert.equal(same.changed, false);
  assert.equal(same.data.secrets.K.updatedAt, '2026-01-01T00:00:00.000Z', 'updatedAt not bumped');
  const tie = mergeGroup({ ...base, secrets: { K: e('mine', '2026-01-01T00:00:00.000Z') } }, { ...base, secrets: { K: e('theirs', '2026-01-01T00:00:00.000Z') } });
  assert.deepEqual(tie.report.conflicts, ['K']);
  assert.equal(tie.data.secrets.K.value, 'mine');
  assert.equal(tie.changed, false);
});

test('tie conflict end to end: both sides keep their value and say so', async () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  m.set(m.b, 'g', 'K', V2);
  const stamp = '2026-03-01T00:00:00.000Z';
  for (const home of [m.a, m.b]) {
    const v = await openVault(home, {});
    const d = v.readGroup('g');
    d.secrets.K.updatedAt = stamp;
    v.writeGroup(d);
  }
  const r = JSON.parse(m.run(['sync', 'my-server', '--json']).stdout);
  assert.deepEqual(r.local.groups[0].conflicts, ['K']);
  assert.deepEqual(r.remote.groups[0].conflicts, ['K']);
  assert.equal(m.value(m.a, 'g', 'K'), V1);
  assert.equal(m.value(m.b, 'g', 'K'), V2);
  assert.match(m.run(['sync', 'my-server']).stdout, /conflict g\/K/);
});

test('tombstones: a delete propagates both ways; a set after a delete wins', async () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  m.set(m.a, 'g', 'KEEP', V3);
  ok(m.run(['push', 'my-server']));
  await sleep(15);
  ok(m.run(['rm', 'g', 'K', '--yes']));
  assert.equal(m.run(['ls', 'g']).stdout.includes('K '), false);
  const r = JSON.parse(m.run(['push', 'my-server', '--json']).stdout);
  assert.deepEqual(r.remote.groups[0].deleted, ['K']);
  assert.equal(m.onB(['get', 'g', 'K']).status, 1);
  assert.equal(m.value(m.b, 'g', 'KEEP'), V3);
  // delete on B, pull to A
  await sleep(15);
  ok(m.onB(['rm', 'g', 'KEEP', '--yes']));
  const p = JSON.parse(m.run(['pull', 'my-server', '--json']).stdout);
  assert.deepEqual(p.local.groups[0].deleted, ['KEEP']);
  assert.equal(m.run(['get', 'g', 'KEEP']).status, 1);
  // set after delete wins on the next sync
  await sleep(15);
  m.set(m.b, 'g', 'K', V2);
  ok(m.run(['sync', 'my-server']));
  assert.equal(m.value(m.a, 'g', 'K'), V2);
  // tombstones are invisible everywhere
  assert.equal(JSON.parse(m.run(['ls', 'g', '--json']).stdout).length, 1);
  assert.equal(JSON.parse(m.run(['groups', '--json']).stdout)[0].count, 1);
  assert.equal(m.run(['export', 'g'], { env: { SKV_ACTOR: 'user' } }).stdout.includes('KEEP'), false);
});

test('rm --all leaves tombstones: the group disappears and the deletion syncs', async () => {
  const m = machines();
  m.set(m.a, 'g', 'K1', V1);
  m.set(m.a, 'g', 'K2', V2);
  ok(m.run(['sync', 'my-server']));
  await sleep(15);
  ok(m.run(['rm', 'g', '--all', '--yes']));
  assert.deepEqual(JSON.parse(m.run(['groups', '--json']).stdout), []);
  assert.equal(m.run(['ls', 'g']).status, 1);
  ok(m.run(['sync', 'my-server']));
  assert.deepEqual(JSON.parse(m.onB(['groups', '--json']).stdout), []);
  assert.equal(m.onB(['get', 'g', 'K1']).status, 1);
  // the group can be recreated
  m.set(m.a, 'g', 'K3', V3);
  assert.equal(JSON.parse(m.run(['groups', '--json']).stdout)[0].count, 1);
});

test('file secrets travel byte for byte', async () => {
  const m = machines();
  const f = path.join(tmpDir(), 'release.jks');
  const bytes = Buffer.from([0, 1, 2, 250, 251, 252, 0, 255]);
  fs.writeFileSync(f, bytes);
  ok(m.run(['set-file', 'android', 'KEYSTORE', f]));
  ok(m.run(['push', 'my-server']));
  const got = (await openVault(m.b, {})).getSecret('android', 'KEYSTORE');
  assert.deepEqual(Buffer.from(got.value, 'base64'), bytes);
  const ls = JSON.parse(m.onB(['ls', 'android', '--json']).stdout)[0];
  assert.equal(ls.type, 'file');
  assert.equal(ls.filename, 'release.jks');
});

test('--dry-run reports but writes nothing on either side', () => {
  const m = machines();
  m.set(m.a, 'g', 'ONLY_A', V1);
  m.set(m.b, 'g', 'ONLY_B', V2);
  const snap = () => [m.a, m.b].map((h) => fs.readFileSync(path.join(h, 'vault', 'g.enc'), 'utf8'));
  const before = snap();
  const logsBefore = logEntries(m.b).length;
  for (const cmd of ['push', 'pull', 'sync']) {
    const r = m.run([cmd, 'my-server', '--dry-run', '--json']);
    ok(r);
    assert.equal(JSON.parse(r.stdout).dryRun, true);
  }
  const s = JSON.parse(m.run(['sync', 'my-server', '--dry-run', '--json']).stdout);
  assert.deepEqual(s.local.groups[0].added, ['ONLY_B']);
  assert.deepEqual(s.remote.groups[0].added, ['ONLY_A']);
  assert.deepEqual(snap(), before);
  assert.ok(logEntries(m.b).length > logsBefore, 'the dry run is still logged');
});

test('group filter limits what is synced', () => {
  const m = machines();
  m.set(m.a, 'one', 'A', V1);
  m.set(m.a, 'two', 'B', V2);
  m.set(m.a, 'three', 'C', V3);
  ok(m.run(['push', 'my-server', 'one,three']));
  assert.deepEqual(JSON.parse(m.onB(['groups', '--json']).stdout).map((g) => g.group).sort(), ['one', 'three']);
  assert.equal(m.run(['push', 'my-server', 'missing']).status, 1);
  // a group that exists on one side only still syncs
  m.set(m.b, 'four', 'D', V1);
  ok(m.run(['sync', 'my-server', 'four']));
  assert.equal(m.value(m.a, 'four', 'D'), V1);
});

test('a remote without _sync, a remote skv that is not found, and the --remote-skv / config override', () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  const old = m.run(['push', 'my-server', '--remote-skv', 'oldskv']);
  assert.equal(old.status, 1);
  assert.match(old.stderr, /update skv on my-server/);
  const missing = m.run(['push', 'my-server', '--remote-skv', 'nothere']);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /--remote-skv/);
  ok(m.run(['config', 'set', 'remote-skv', 'my-server', 'oldskv']));
  assert.match(m.run(['config']).stdout, /remote-skv my-server\s+oldskv/);
  assert.equal(JSON.parse(m.run(['config', '--json']).stdout)['remote-skv']['my-server'], 'oldskv');
  assert.match(m.run(['push', 'my-server']).stderr, /update skv on my-server/, 'the configured command is used');
  ok(m.run(['push', 'my-server', '--remote-skv', 'skv']));
  ok(m.run(['config', 'unset', 'remote-skv', 'my-server']));
  ok(m.run(['push', 'my-server']));
  const calls = fs.readFileSync(m.logFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.ok(calls.every((c) => c.host === 'my-server' && c.argv.includes('BatchMode=yes') && c.argv.includes('ConnectTimeout=10')));
  assert.ok(calls.some((c) => c.remote === 'skv _sync receive'));
});

test('local _sync send is refused for agents and prints no values', () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  const r = skv(m.a, ['_sync', 'send'], { env: { SKV_ACTOR: 'agent' } });
  assert.equal(r.status, 1);
  assert.equal((r.stdout + r.stderr).includes(V1), false);
  assert.match(r.stdout, /disabled for agents/);
  assert.ok(logEntries(m.a).some((e) => e.action === 'sync-send' && e.denied));
  // for a user it streams the group
  const u = skv(m.a, ['_sync', 'send']);
  ok(u);
  assert.match(u.stdout, /"protocol":1/);
  // push/pull/sync themselves work for agents
  ok(m.run(['push', 'my-server'], { env: { SKV_ACTOR: 'agent' } }));
  ok(m.run(['pull', 'my-server'], { env: { SKV_ACTOR: 'agent' } }));
});

test('hosts starting with - are rejected, and ssh gets the host as one argument', () => {
  const m = machines();
  for (const cmd of ['push', 'pull', 'sync']) {
    const r = m.run([cmd, '-oProxyCommand=evil']);
    assert.notEqual(r.status, 0);
  }
  const r = m.run(['push', '--', 'x']);
  assert.notEqual(r.status, 0);
  assert.equal(m.run(['config', 'set', 'remote-skv', '-bad', 'skv']).status, 2);
  assert.equal(fs.existsSync(m.logFile), false, 'ssh was never started');
  m.set(m.a, 'g', 'K', V1);
  ok(m.run(['push', 'user@100.1.2.3']));
  assert.equal(JSON.parse(fs.readFileSync(m.logFile, 'utf8').trim().split('\n')[0]).host, 'user@100.1.2.3');
});

test('a passphrase-locked remote fails with a clear message', () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  ok(skv(m.b, ['passphrase', 'set'], { input: 'correct horse battery\n' }));
  const r = m.run(['push', 'my-server']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /locked: run `skv unlock` on my-server/);
});

test('logs and reports never contain values; both sides log', () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  m.set(m.b, 'g', 'J', V2);
  const out = m.run(['sync', 'my-server']);
  const json = m.run(['sync', 'my-server', '--json']);
  for (const text of [out.stdout, out.stderr, json.stdout, json.stderr, fs.readFileSync(path.join(m.a, 'log.jsonl'), 'utf8'), fs.readFileSync(path.join(m.b, 'log.jsonl'), 'utf8')]) {
    assert.equal(text.includes(V1) || text.includes(V2), false);
  }
  const a = logEntries(m.a).find((e) => e.action === 'sync');
  assert.equal(a.peer, 'my-server');
  assert.ok(a.keys.includes('g/J'));
  const b = logEntries(m.b).map((e) => e.action);
  assert.ok(b.includes('sync-send') && b.includes('sync-receive'));
  assert.ok(logEntries(m.b).find((e) => e.action === 'sync-receive').keys.includes('g/K'));
});

test('old vault files without tombstones keep working; doctor reports tombstone counts', () => {
  const m = machines();
  m.set(m.a, 'g', 'K', V1);
  m.set(m.a, 'g', 'L', V2);
  assert.equal(JSON.parse(m.run(['ls', 'g', '--json']).stdout).length, 2);
  ok(m.run(['rm', 'g', 'L', '--yes']));
  assert.match(m.run(['doctor']).stdout, /g\.enc: 1 secret\(s\), 1 tombstone\(s\)/);
});
