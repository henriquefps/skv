import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { decrypt, encrypt, fingerprint, generateKey, parseKey } from '../src/crypto.mjs';
import { initHome as initHomeCore, openVault } from '../src/home.mjs';
import { envKeyProvider, fileKeyProvider, loadKey } from '../src/keys.mjs';
import { Vault } from '../src/vault.mjs';
import { tmpHome } from './helpers.mjs';

test('encrypt/decrypt round trip, fresh IV each time', () => {
  const key = generateKey();
  const a = encrypt(key, 'héllo wörld', 'openai');
  const b = encrypt(key, 'héllo wörld', 'openai');
  assert.equal(a.alg, 'aes-256-gcm');
  assert.equal(a.v, 1);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.data, b.data);
  assert.equal(decrypt(key, a, 'openai'), 'héllo wörld');
  assert.equal(Buffer.from(a.iv, 'base64').length, 12);
  assert.equal(Buffer.from(a.tag, 'base64').length, 16);
});

test('tampered ciphertext, tag or iv is rejected', () => {
  const key = generateKey();
  const env = encrypt(key, 'secret value', 'g');
  const flip = (b64) => {
    const buf = Buffer.from(b64, 'base64');
    buf[0] ^= 1;
    return buf.toString('base64');
  };
  for (const field of ['data', 'tag', 'iv']) {
    assert.throws(() => decrypt(key, { ...env, [field]: flip(env[field]) }, 'g'), { code: 'decrypt' }, field);
  }
});

test('wrong key is rejected', () => {
  const env = encrypt(generateKey(), 'x', 'g');
  assert.throws(() => decrypt(generateKey(), env, 'g'), { code: 'decrypt' });
});

test('AAD binds the envelope to its group: swapping files is detected', () => {
  const home = tmpHome();
  initHomeCore(home, {});
  const vault = openVault(home, {});
  vault.setSecrets('alpha', [{ key: 'A', value: 'aaa' }]);
  vault.setSecrets('beta', [{ key: 'B', value: 'bbb' }]);
  const dir = path.join(home, 'vault');
  fs.copyFileSync(path.join(dir, 'alpha.enc'), path.join(dir, 'beta.enc'));
  assert.throws(() => vault.readGroup('beta'), { code: 'decrypt' });
  assert.equal(vault.readGroup('alpha').secrets.A.value, 'aaa');
});

test('fingerprint is deterministic per key and short', () => {
  const key = generateKey();
  assert.match(fingerprint(key, 'v'), /^[0-9a-f]{8}$/);
  assert.equal(fingerprint(key, 'v'), fingerprint(key, 'v'));
  assert.notEqual(fingerprint(key, 'v'), fingerprint(key, 'w'));
  assert.notEqual(fingerprint(key, 'v'), fingerprint(generateKey(), 'v'));
});

test('key providers: SKV_KEY wins over the key file; bad keys are clear errors', () => {
  const home = tmpHome();
  initHomeCore(home, {});
  const fileKey = fileKeyProvider(home).load();
  const other = generateKey();
  assert.deepEqual(loadKey(home, { SKV_KEY: other.toString('base64') }), other);
  assert.deepEqual(loadKey(home, {}), fileKey);
  assert.throws(() => envKeyProvider({ SKV_KEY: 'c2hvcnQ=' }).load(), { code: 'bad-key' });
  assert.throws(() => parseKey('not base64!!'), { code: 'bad-key' });
  assert.throws(() => loadKey(tmpHome(), {}), { code: 'no-key' });
});

test('vault files contain no plaintext', () => {
  const home = tmpHome();
  initHomeCore(home, {});
  const vault = openVault(home, {});
  vault.setSecrets('g', [{ key: 'TOKEN', value: 'plaintext-marker-123' }]);
  const raw = fs.readFileSync(path.join(home, 'vault', 'g.enc'), 'utf8');
  assert.doesNotMatch(raw, /plaintext-marker|TOKEN/);
  assert.ok(new Vault(home, loadKey(home, {})).readGroup('g'));
});
