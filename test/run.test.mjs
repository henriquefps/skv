import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { materialize, resolveWindowsCommand, spawnPlan } from '../src/run.mjs';

test('materialize: strings become env vars, files go to a private temp file removed by cleanup', () => {
  const { env, tmpDir, cleanup } = materialize(
    [
      { key: 'TOKEN', type: 'string', value: 't' },
      { key: 'JKS', type: 'file', value: Buffer.from([0, 1, 2, 255]).toString('base64'), filename: 'upload.jks' },
    ],
    { KEEP: '1' },
  );
  assert.equal(env.TOKEN, 't');
  assert.equal(env.KEEP, '1');
  assert.ok(env.JKS.endsWith('upload.jks'));
  assert.deepEqual([...fs.readFileSync(env.JKS)], [0, 1, 2, 255]);
  if (process.platform !== 'win32') assert.equal(fs.statSync(env.JKS).mode & 0o777, 0o600);
  cleanup();
  assert.equal(fs.existsSync(tmpDir), false);
});

test('materialize: a hostile filename cannot escape the temp folder', () => {
  const { env, tmpDir, cleanup } = materialize([{ key: 'F', type: 'file', value: '', filename: '../../evil' }], {});
  assert.ok(env.F.startsWith(tmpDir));
  cleanup();
});

test('spawnPlan: POSIX spawns the command directly', () => {
  assert.deepEqual(spawnPlan('node', ['-v'], { platform: 'linux' }), { file: 'node', args: ['-v'], options: {} });
});

test('spawnPlan: Windows resolves PATHEXT, runs .exe directly and .cmd through cmd.exe with escaping', () => {
  const files = new Set(['C:\\bin\\node.EXE', 'C:\\npm\\npx.CMD']);
  const opts = { platform: 'win32', exists: (f) => files.has(f), cwd: 'C:\\work', env: { Path: 'C:\\bin;C:\\npm', PATHEXT: '.EXE;.CMD', ComSpec: 'C:\\Windows\\cmd.exe' } };
  assert.equal(resolveWindowsCommand('node', opts.env, opts), 'C:\\bin\\node.EXE');
  assert.equal(resolveWindowsCommand('missing', opts.env, opts), null);
  assert.deepEqual(spawnPlan('node', ['a b'], opts), { file: 'C:\\bin\\node.EXE', args: ['a b'], options: {} });
  const p = spawnPlan('npx', ['hello world', 'a&b'], opts);
  assert.equal(p.file, 'C:\\Windows\\cmd.exe');
  assert.deepEqual(p.args.slice(0, 3), ['/d', '/s', '/c']);
  assert.equal(p.args[3], '"C:\\npm\\npx.CMD ^"hello^ world^" ^"a^&b^""');
  assert.deepEqual(p.options, { windowsVerbatimArguments: true });
});
