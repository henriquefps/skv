import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { FILE_MODE } from './fsutil.mjs';
import { isWindows } from './paths.mjs';

/**
 * Turn collected secrets into env vars. File secrets are written to a private temp folder (0700, files 0600)
 * and the variable holds the path. Returns { env, tmpDir, cleanup }.
 */
export function materialize(secrets, baseEnv = process.env) {
  const env = { ...baseEnv };
  let tmpDir = null;
  for (const s of secrets) {
    if (s.type === 'file') {
      tmpDir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'skv-'));
      const dir = path.join(tmpDir, s.key);
      fs.mkdirSync(dir, { mode: 0o700 });
      const file = path.join(dir, path.basename(s.filename || s.key));
      fs.writeFileSync(file, Buffer.from(s.value, 'base64'), { mode: FILE_MODE });
      env[s.key] = file;
    } else {
      env[s.key] = s.value;
    }
  }
  const cleanup = () => {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  };
  return { env, tmpDir, cleanup };
}

/** Case-insensitive env lookup (Windows env names are case-insensitive, e.g. Path vs PATH). */
function envGet(env, name, platform) {
  if (!isWindows(platform)) return env[name];
  const k = Object.keys(env).find((x) => x.toUpperCase() === name.toUpperCase());
  return k ? env[k] : undefined;
}

/** Windows: find `cmd` on PATH using PATHEXT, like the shell would. Returns the full path or null. */
export function resolveWindowsCommand(cmd, env = process.env, { exists = fs.existsSync, cwd = process.cwd() } = {}) {
  const exts = (envGet(env, 'PATHEXT', 'win32') || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const hasExt = path.win32.extname(cmd) !== '';
  const candidates = (base) => (hasExt ? [base, ...exts.map((e) => base + e)] : exts.map((e) => base + e));
  const hasDir = /[\\/]/.test(cmd);
  const dirs = hasDir ? [''] : [cwd, ...(envGet(env, 'PATH', 'win32') || '').split(';').filter(Boolean)];
  for (const dir of dirs) {
    for (const c of candidates(hasDir ? path.win32.resolve(cwd, cmd) : path.win32.join(dir, cmd))) {
      if (exists(c)) return c;
    }
  }
  return null;
}

// cmd.exe metacharacters (same rules as the cross-spawn package).
const META = /([()\][%!^"`<>&|;, *?])/g;

function escapeCmdArg(arg, doubleEscape) {
  let a = String(arg);
  a = a.replace(/(?=(\\+?)?)\1"/g, '$1$1\\"');
  a = a.replace(/(?=(\\+?)?)\1$/, '$1$1');
  a = `"${a}"`.replace(META, '^$1');
  return doubleEscape ? a.replace(META, '^$1') : a;
}

/**
 * How to spawn `cmd args` without a shell. On Windows, .cmd/.bat files can't be spawned directly
 * (Node refuses since CVE-2024-27980), so they go through `cmd.exe /d /s /c` with every argument escaped.
 */
export function spawnPlan(cmd, args, { env = process.env, platform = process.platform, exists, cwd } = {}) {
  if (!isWindows(platform)) return { file: cmd, args, options: {} };
  const resolved = resolveWindowsCommand(cmd, env, { exists, cwd }) ?? cmd;
  if (!/\.(cmd|bat)$/i.test(resolved)) return { file: resolved, args, options: {} };
  const shim = /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i.test(resolved);
  const line = [resolved.replace(META, '^$1'), ...args.map((a) => escapeCmdArg(a, shim))].join(' ');
  const comspec = envGet(env, 'COMSPEC', platform) || 'cmd.exe';
  return { file: comspec, args: ['/d', '/s', '/c', `"${line}"`], options: { windowsVerbatimArguments: true } };
}

const FORWARD = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGBREAK', 'SIGQUIT'];

/**
 * Run a command with `env`, stdio inherited. Forwards signals to the child, calls `cleanup` when it ends,
 * and resolves to { code, signal }. A command that can't be started resolves to { code: 127, error }.
 */
export function runChild(cmd, args, env, cleanup = () => {}) {
  return new Promise((resolve) => {
    const plan = spawnPlan(cmd, args, { env });
    let child;
    const handlers = new Map();
    const onExit = () => cleanup();
    process.on('exit', onExit);
    const finish = (result) => {
      for (const [sig, h] of handlers) process.off(sig, h);
      cleanup();
      process.off('exit', onExit);
      resolve(result);
    };
    try {
      child = spawn(plan.file, plan.args, { stdio: 'inherit', env, ...plan.options });
    } catch (error) {
      return finish({ code: 127, error });
    }
    for (const sig of FORWARD) {
      const h = () => {
        try {
          child.kill(sig);
        } catch {}
      };
      try {
        process.on(sig, h);
        handlers.set(sig, h);
      } catch {}
    }
    child.on('error', (error) => finish({ code: error.code === 'ENOENT' ? 127 : 126, error }));
    child.on('exit', (code, signal) => finish({ code, signal }));
  });
}
