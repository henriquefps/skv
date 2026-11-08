// A stand-in for `ssh` used by the sync tests (SKV_SSH points here). It ignores the ssh options and the host,
// and runs the remote command against the "remote machine": a second SKV_HOME given in SKV_FAKE_REMOTE_HOME.
//   skv ...      -> node bin/skv.mjs ... (the real remote skv)
//   oldskv ...   -> an skv that predates `_sync`
//   anything else-> "command not found" (127)
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// `node --test` also loads every file under test/: do nothing when run outside the sync tests.
if (!process.env.SKV_FAKE_REMOTE_HOME) process.exit(0);

const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'skv.mjs');
const args = process.argv.slice(2);
let i = 0;
while (args[i] === '-o') i += 2;
const host = args[i];
const remote = args.slice(i + 1).join(' ');
if (process.env.SKV_FAKE_LOG) fs.appendFileSync(process.env.SKV_FAKE_LOG, `${JSON.stringify({ argv: args, host, remote })}\n`);
const [first, ...rest] = remote.split(' ');
if (first === 'oldskv') {
  process.stderr.write(`skv: unknown command: ${rest[0]}\n\nskv: secrets keeper vault\n`);
  process.exit(2);
}
if (first !== 'skv') {
  process.stderr.write(`${first}: command not found\n`);
  process.exit(127);
}
// ssh does not forward the caller's environment: the remote process has no agent markers and runs as the user.
const env = { ...process.env, SKV_HOME: process.env.SKV_FAKE_REMOTE_HOME, SKV_ACTOR: 'user' };
delete env.CLAUDECODE;
for (const k of Object.keys(env)) if (k.startsWith('CODEX_')) delete env[k];
const child = spawn(process.execPath, [BIN, ...rest], { stdio: ['pipe', 'inherit', 'inherit'], env });
process.stdin.pipe(child.stdin);
child.on('close', (code) => process.exit(code ?? 1));
