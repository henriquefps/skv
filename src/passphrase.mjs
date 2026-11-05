import crypto from 'node:crypto';
import { KEY_BYTES } from './crypto.mjs';
import { SkvError } from './errors.mjs';

/**
 * Passphrase wrapping of the master key. The master key itself never changes: it is encrypted with a key derived
 * from the passphrase (scrypt) using AES-256-GCM, so the vault is not re-encrypted and a raw-key backup keeps working.
 *
 * Envelope (the content of $SKV_HOME/key when a passphrase is set):
 *   { v: 1, kdf: "scrypt", params: { N, r, p, keylen }, salt, iv, tag, data }   (binary fields base64)
 */
export const KDF_PARAMS = Object.freeze({ N: 2 ** 17, r: 8, p: 1, keylen: 32 });
export const MIN_PASSPHRASE = 8;
const AAD = Buffer.from('skv-master-key', 'utf8');
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** scrypt needs 128 * N * r bytes; give it headroom over Node's 32 MiB default. */
const maxmem = ({ N, r }) => 256 * N * r;

function deriveKey(passphrase, salt, params) {
  const { N, r, p, keylen } = params;
  return crypto.scryptSync(Buffer.from(String(passphrase).normalize('NFC'), 'utf8'), salt, keylen, { N, r, p, maxmem: maxmem(params) });
}

export function assertPassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE) {
    throw new SkvError('weak-passphrase', `the passphrase must be at least ${MIN_PASSPHRASE} characters`);
  }
  return passphrase;
}

/** Wrap a 32-byte master key with a passphrase. `params` is only overridable for tests of the format. */
export function wrapKey(masterKey, passphrase, params = KDF_PARAMS) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_BYTES) throw new TypeError('master key must be 32 bytes');
  const salt = crypto.randomBytes(SALT_BYTES);
  const iv = crypto.randomBytes(IV_BYTES);
  const kek = deriveKey(passphrase, salt, params);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(AAD);
    const data = Buffer.concat([cipher.update(masterKey), cipher.final()]);
    return {
      v: 1,
      kdf: 'scrypt',
      params: { N: params.N, r: params.r, p: params.p, keylen: params.keylen },
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
  } finally {
    kek.fill(0);
  }
}

/** True when `envelope` looks like a wrapped key (structure only, no decryption). */
export function isWrappedEnvelope(envelope) {
  return Boolean(
    envelope &&
      envelope.v === 1 &&
      envelope.kdf === 'scrypt' &&
      envelope.params &&
      [envelope.params.N, envelope.params.r, envelope.params.p, envelope.params.keylen].every(Number.isInteger) &&
      ['salt', 'iv', 'tag', 'data'].every((f) => typeof envelope[f] === 'string'),
  );
}

/** Unwrap the master key; a wrong passphrase (or a modified file) is SkvError('bad-passphrase'). */
export function unwrapKey(envelope, passphrase) {
  if (!isWrappedEnvelope(envelope)) throw new SkvError('bad-key', 'the key file is not a valid passphrase envelope');
  const { params } = envelope;
  if (params.keylen !== 32 || params.N < 2 ** 14 || params.N > 2 ** 22 || params.r > 32 || params.p > 16) {
    throw new SkvError('bad-key', 'the key file has unsupported scrypt parameters');
  }
  const kek = deriveKey(passphrase, Buffer.from(envelope.salt, 'base64'), params);
  try {
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('bad iv/tag');
    const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(AAD);
    decipher.setAuthTag(tag);
    const key = Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]);
    if (key.length !== KEY_BYTES) throw new Error('bad key length');
    return key;
  } catch {
    throw new SkvError('bad-passphrase', 'wrong passphrase (or the key file was modified)');
  } finally {
    kek.fill(0);
  }
}
