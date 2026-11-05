import { SkvError } from './errors.mjs';

const LINE_KEY = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*/;
const DQ_ESCAPES = { n: '\n', r: '\r', t: '\t', '\\': '\\', '"': '"', $: '$' };

/**
 * Parse a dotenv file into [{ key, value, line }].
 * Supports `# comments`, `export KEY=...`, unquoted values with ` # inline comments`, 'single' (literal) and
 * "double" quotes (escapes \n \r \t \\ \" \$), and quoted values spanning several lines.
 */
export function parseDotenv(text) {
  const src = String(text).replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  const out = [];
  let i = 0;
  let line = 1;
  while (i < src.length) {
    const eol = src.indexOf('\n', i) === -1 ? src.length : src.indexOf('\n', i);
    const raw = src.slice(i, eol);
    const startLine = line;
    if (/^\s*(#.*)?$/.test(raw)) {
      i = eol + 1;
      line++;
      continue;
    }
    const m = LINE_KEY.exec(raw);
    if (!m) throw new SkvError('parse', `line ${startLine}: expected KEY=value`);
    const key = m[1];
    let j = i + m[0].length;
    const q = src[j];
    let value;
    if (q === '"' || q === "'" || q === '`') {
      j++;
      value = '';
      for (;;) {
        if (j >= src.length) throw new SkvError('parse', `line ${startLine}: unterminated ${q}quoted value for ${key}`);
        const ch = src[j];
        if (ch === q) break;
        if (ch === '\n') line++;
        if (q === '"' && ch === '\\' && j + 1 < src.length && src[j + 1] in DQ_ESCAPES) {
          value += DQ_ESCAPES[src[j + 1]];
          j += 2;
          continue;
        }
        value += ch;
        j++;
      }
      j++;
      const restEnd = src.indexOf('\n', j) === -1 ? src.length : src.indexOf('\n', j);
      const rest = src.slice(j, restEnd);
      if (!/^\s*(#.*)?$/.test(rest)) throw new SkvError('parse', `line ${line}: unexpected text after the closing quote of ${key}`);
      i = restEnd + 1;
    } else {
      value = raw.slice(m[0].length).replace(/(^|\s)#.*$/, '').trim();
      i = eol + 1;
    }
    out.push({ key, value, line: startLine });
    line++;
  }
  return out;
}

/** Quote a value so that parseDotenv reads it back unchanged. */
export function quoteDotenv(value) {
  if (/^[A-Za-z0-9_./:@+,=%-]*$/.test(value)) return value;
  if (!/['\n\r]/.test(value)) return `'${value}'`;
  return `"${value.replace(/[\\"$\n\r\t]/g, (c) => ({ '\\': '\\\\', '"': '\\"', $: '\\$', '\n': '\\n', '\r': '\\r', '\t': '\\t' })[c])}"`;
}

export function formatDotenv(entries) {
  return entries.map(({ key, value }) => `${key}=${quoteDotenv(value)}\n`).join('');
}
