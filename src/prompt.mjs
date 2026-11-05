import { SkvError } from './errors.mjs';

/** Read all of stdin as a Buffer. */
export async function readStdin(stream = process.stdin) {
  const chunks = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}

/** Strip a single trailing newline (from `echo` or a here-string); `printf '%s'` input is kept as is. */
export const stripOneNewline = (s) => s.replace(/\r?\n$/, '');

/** Prompt on the TTY without echoing what is typed. */
export function hiddenPrompt(question, { input = process.stdin, output = process.stderr } = {}) {
  return new Promise((resolve, reject) => {
    output.write(question);
    let value = '';
    const wasRaw = input.isRaw;
    input.setRawMode(true);
    input.resume();
    input.setEncoding('utf8');
    const done = (err) => {
      input.setRawMode(wasRaw);
      input.pause();
      input.off('data', onData);
      output.write('\n');
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n' || ch === '\u0004') return done();
        if (ch === '\u0003') return done(new SkvError('aborted', 'aborted'));
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    input.on('data', onData);
  });
}

/** The secret value for `set`: piped stdin, or a hidden prompt on a TTY. Never argv. */
export async function readSecretValue(label) {
  let value;
  if (process.stdin.isTTY) value = await hiddenPrompt(`value for ${label} (hidden): `);
  else value = stripOneNewline((await readStdin()).toString('utf8'));
  if (!value) throw new SkvError('empty', 'empty value: pipe it on stdin (printf \'%s\' "$VALUE" | skv set ...) or type it at the prompt');
  return value;
}
