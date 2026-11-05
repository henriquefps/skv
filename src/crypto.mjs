import crypto from 'node:crypto';
import { SkvError } from './errors.mjs';

export const ALG = 'aes-256-gcm';
export const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export const generateKey = () => crypto.randomBytes(KEY_BYTES);

/** Parse a base64 master key; throws unless it is exactly 32 bytes. */
export function parseKey(text, source = 'key') {
  const raw = String(text).trim();
  const key = Buffer.from(raw, 'base64');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw) || key.length !== KEY_BYTES) {
    throw new SkvError('bad-key', `${source} is not a base64 ${KEY_BYTES}-byte key`);
  }
  return key;
}

/** Encrypt a UTF-8 string; `aad` (the group name) is authenticated so envelopes can't be swapped between files. */
export function encrypt(key, plaintext, aad) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALG, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { v: 1, alg: ALG, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
}

/** Decrypt an envelope; any tampering, wrong key or wrong AAD is a `decrypt` error. */
export function decrypt(key, envelope, aad) {
  if (!envelope || envelope.v !== 1 || envelope.alg !== ALG) throw new SkvError('decrypt', 'unsupported envelope format');
  try {
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('bad iv/tag');
    const decipher = crypto.createDecipheriv(ALG, key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw new SkvError('decrypt', `cannot decrypt "${aad}": wrong key, or the file was modified or renamed`);
  }
}

/** First 8 hex chars of HMAC-SHA256(key, value): tells whether two values match without storing them. */
export function fingerprint(key, value) {
  return crypto.createHmac('sha256', key).update(value).digest('hex').slice(0, 8);
}
