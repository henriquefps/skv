import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatDotenv, parseDotenv } from '../src/dotenv.mjs';

const obj = (text) => Object.fromEntries(parseDotenv(text).map((e) => [e.key, e.value]));

test('dotenv: comments, blank lines, export prefix, spaces, inline comments', () => {
  const text = [
    '# a comment',
    '',
    'PLAIN=abc',
    'export EXPORTED=yes',
    '  SPACED = padded value  ',
    'INLINE=value # comment',
    'HASH=a#b',
    'EMPTY=',
    'URL=https://x.test/a?b=c&d=e',
    '   # indented comment',
  ].join('\n');
  assert.deepEqual(obj(text), {
    PLAIN: 'abc',
    EXPORTED: 'yes',
    SPACED: 'padded value',
    INLINE: 'value',
    HASH: 'a#b',
    EMPTY: '',
    URL: 'https://x.test/a?b=c&d=e',
  });
});

test('dotenv: quotes and escapes', () => {
  const text = [
    `SINGLE='literal $HOME \\n # not a comment'`,
    'DOUBLE="tab\\there \\"q\\" \\\\ \\$x" # trailing comment',
    'BACKTICK=`it\'s "fine"`',
    "EXPORTED_Q='x'",
  ].join('\n');
  assert.deepEqual(obj(text), {
    SINGLE: 'literal $HOME \\n # not a comment',
    DOUBLE: 'tab\there "q" \\ $x',
    BACKTICK: `it's "fine"`,
    EXPORTED_Q: 'x',
  });
});

test('dotenv: multiline quoted values and CRLF', () => {
  const text = 'KEY="-----BEGIN KEY-----\nline2\n-----END KEY-----"\r\nNEXT=1\r\nSQ=\'a\nb\'\nESC="a\\nb"\n';
  assert.deepEqual(obj(text), { KEY: '-----BEGIN KEY-----\nline2\n-----END KEY-----', NEXT: '1', SQ: 'a\nb', ESC: 'a\nb' });
  assert.deepEqual(parseDotenv(text).map((e) => e.line), [1, 4, 5, 7]);
});

test('dotenv: errors carry the line number', () => {
  assert.throws(() => parseDotenv('A=1\nnot a pair\n'), /line 2/);
  assert.throws(() => parseDotenv('A="unterminated\n'), /line 1: unterminated/);
  assert.throws(() => parseDotenv('A="x" junk'), /after the closing quote/);
});

test('dotenv: format then parse is lossless', () => {
  const values = {
    A: 'simple',
    B: 'with space',
    C: "it's",
    D: 'multi\nline\r\nwith "quotes" and \\ and $VAR and \t tab',
    E: '',
    F: '# looks like a comment',
    G: 'sk-abc_123/+=',
  };
  const text = formatDotenv(Object.entries(values).map(([key, value]) => ({ key, value })));
  assert.deepEqual(obj(text), values);
});
