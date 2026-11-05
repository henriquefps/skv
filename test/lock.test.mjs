import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { acquireLock, withLock } from '../src/lock.mjs';
import { tmpDir } from './helpers.mjs';

test('lock: exclusive while held, removed on release', () => {
  const file = path.join(tmpDir(), 'g.lock');
  const release = acquireLock(file);
  assert.ok(fs.existsSync(file));
  assert.throws(() => acquireLock(file, { timeoutMs: 100 }), { code: 'locked' });
  release();
  assert.equal(fs.existsSync(file), false);
  assert.equal(withLock(file, () => 42), 42);
  assert.equal(fs.existsSync(file), false);
});

test('lock: released when the callback throws', () => {
  const file = path.join(tmpDir(), 'g.lock');
  assert.throws(() => withLock(file, () => { throw new Error('boom'); }), /boom/);
  assert.equal(fs.existsSync(file), false);
});

test('lock: a stale lock is taken over; release does not remove a lock someone else took', () => {
  const file = path.join(tmpDir(), 'g.lock');
  fs.writeFileSync(file, 'dead process\n');
  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(file, old, old);
  const release = acquireLock(file, { timeoutMs: 100 });
  assert.notEqual(fs.readFileSync(file, 'utf8'), 'dead process\n');
  fs.writeFileSync(file, 'someone else\n');
  release();
  assert.equal(fs.readFileSync(file, 'utf8'), 'someone else\n');
});
