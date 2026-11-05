import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { initHome, openVault } from '../src/home.mjs';
import { HISTORY_LIMIT, isGroupName, isKeyName, parseGroupList } from '../src/vault.mjs';
import { tmpHome } from './helpers.mjs';

const fresh = () => {
  const home = tmpHome();
  initHome(home, {});
  return openVault(home, {});
};

test('name rules', () => {
  for (const ok of ['openai', 'a', 'my-app-2', 'x'.repeat(64)]) assert.ok(isGroupName(ok), ok);
  for (const bad of ['', 'Open', 'a_b', '-a', 'x'.repeat(65), '../x', 'a/b']) assert.equal(isGroupName(bad), false, bad);
  for (const ok of ['A', '_X', 'OPENAI_API_KEY', 'K2']) assert.ok(isKeyName(ok), ok);
  for (const bad of ['', 'a', '2A', 'A-B', 'A B']) assert.equal(isKeyName(bad), false, bad);
  assert.deepEqual(parseGroupList('a,b,a'), ['a', 'b']);
  assert.throws(() => parseGroupList('a,B'), { code: 'usage' });
});

test('set reports added / changed / unchanged and keeps the last 5 values', () => {
  const v = fresh();
  assert.equal(v.setSecrets('g', [{ key: 'K', value: 'v0' }])[0].status, 'added');
  assert.equal(v.setSecrets('g', [{ key: 'K', value: 'v0' }])[0].status, 'unchanged');
  for (let i = 1; i <= 7; i++) assert.equal(v.setSecrets('g', [{ key: 'K', value: `v${i}` }])[0].status, 'changed');
  const s = v.getSecret('g', 'K');
  assert.equal(s.value, 'v7');
  assert.equal(s.history.length, HISTORY_LIMIT);
  assert.deepEqual(s.history.map((h) => h.value), ['v6', 'v5', 'v4', 'v3', 'v2']);
  assert.ok(s.history.every((h) => h.replacedAt));
});

test('list and groups never include values', () => {
  const v = fresh();
  v.setSecrets('g', [{ key: 'A', value: 'value-a', note: 'n' }, { key: 'B', value: 'value-b' }], { description: 'desc' });
  const text = JSON.stringify([v.list(), v.list('g'), v.groups()]);
  assert.doesNotMatch(text, /value-a|value-b/);
  assert.deepEqual(v.groups().map((g) => [g.group, g.count, g.description]), [['g', 2, 'desc']]);
  assert.deepEqual(v.list('g').map((s) => [s.key, s.note]), [['A', 'n'], ['B', '']]);
});

test('remove a key; collect detects the same key in two groups', () => {
  const v = fresh();
  v.setSecrets('a', [{ key: 'K', value: '1' }, { key: 'L', value: '2' }]);
  v.setSecrets('b', [{ key: 'K', value: '3' }]);
  assert.throws(() => v.collect(['a', 'b']), { code: 'conflict' });
  v.removeSecret('a', 'K');
  assert.deepEqual(v.collect(['a', 'b']).map((s) => s.key).sort(), ['K', 'L']);
  assert.throws(() => v.getSecret('a', 'K'), { code: 'not-found' });
  assert.throws(() => v.requireGroup('zzz'), { code: 'not-found' });
});

test('writes are atomic: no temp files left behind', () => {
  const v = fresh();
  for (let i = 0; i < 5; i++) v.setSecrets('g', [{ key: 'K', value: String(i) }]);
  assert.deepEqual(fs.readdirSync(path.join(v.home, 'vault')), ['g.enc']);
});

test('init is idempotent and refuses to create a new key over existing groups', () => {
  const v = fresh();
  const key = fs.readFileSync(path.join(v.home, 'key'), 'utf8');
  assert.deepEqual(initHome(v.home, {}).created, []);
  assert.equal(fs.readFileSync(path.join(v.home, 'key'), 'utf8'), key);
  v.setSecrets('g', [{ key: 'K', value: 'x' }]);
  fs.rmSync(path.join(v.home, 'key'));
  assert.throws(() => initHome(v.home, {}), { code: 'no-key' });
  assert.equal(fs.existsSync(path.join(v.home, 'key')), false);
});

test('rollback restores the previous value; a second rollback undoes it', () => {
  const v = fresh();
  v.setSecrets('g', [{ key: 'K', value: 'v1' }]);
  assert.throws(() => v.rollback('g', 'K'), { code: 'no-history' });
  v.setSecrets('g', [{ key: 'K', value: 'v2' }]);
  v.setSecrets('g', [{ key: 'K', value: 'v3' }]);
  const r = v.rollback('g', 'K');
  assert.equal(r.fingerprint, v.fingerprint('v2'));
  assert.equal(r.from, v.fingerprint('v3'));
  assert.doesNotMatch(JSON.stringify(r), /v2|v3/);
  assert.equal(v.getSecret('g', 'K').value, 'v2');
  assert.deepEqual(v.getSecret('g', 'K').history.map((h) => h.value), ['v3', 'v1']);
  v.rollback('g', 'K');
  assert.equal(v.getSecret('g', 'K').value, 'v3');
  assert.deepEqual(v.getSecret('g', 'K').history.map((h) => h.value), ['v2', 'v1']);
  assert.throws(() => v.rollback('g', 'NOPE'), { code: 'not-found' });
  assert.deepEqual(fs.readdirSync(path.join(v.home, 'vault')), ['g.enc'], 'lock file released');
});

test('rollback restores the type and file name of a file secret', () => {
  const v = fresh();
  v.setSecrets('g', [{ key: 'F', value: 'YQ==', type: 'file', filename: 'a.jks' }]);
  v.setSecrets('g', [{ key: 'F', value: 'plain' }]);
  assert.equal(v.getSecret('g', 'F').filename, undefined);
  v.rollback('g', 'F');
  const s = v.getSecret('g', 'F');
  assert.deepEqual([s.type, s.filename, s.value], ['file', 'a.jks', 'YQ==']);
  assert.deepEqual(s.history.map((h) => [h.type ?? 'string', h.value]), [['string', 'plain']]);
});
