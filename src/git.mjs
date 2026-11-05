import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { SkvError } from './errors.mjs';

/** Nearest folder at or above `dir` that contains `.git` (folder or file), or null. */
export function findGitRoot(dir) {
  let cur = path.resolve(dir);
  for (;;) {
    if (fs.existsSync(path.join(cur, '.git'))) return cur;
    const up = path.dirname(cur);
    if (up === cur) return null;
    cur = up;
  }
}

/** Nearest existing folder at or above `p`. */
function existingDir(p) {
  let cur = path.resolve(p);
  while (!fs.existsSync(cur)) {
    const up = path.dirname(cur);
    if (up === cur) break;
    cur = up;
  }
  return cur;
}

/**
 * Refuse to write `file` inside a git work tree unless git says the path is ignored.
 * Throws SkvError('unsafe-path'); returns { repo, ignored } otherwise.
 */
export function assertSafeExportPath(file) {
  const abs = path.resolve(file);
  const repo = findGitRoot(existingDir(path.dirname(abs)));
  if (!repo) return { repo: null, ignored: false };
  const r = spawnSync('git', ['check-ignore', '-q', '--', abs], { cwd: repo, encoding: 'utf8' });
  if (r.error) throw new SkvError('unsafe-path', `${abs} is inside the git repo ${repo} and git is not available to check that it is ignored`);
  if (r.status === 0) return { repo, ignored: true };
  if (r.status === 1) {
    throw new SkvError('unsafe-path', `refusing to write secrets to ${abs}: it is inside the git repo ${repo} and not git-ignored (add it to .gitignore first)`);
  }
  throw new SkvError('unsafe-path', `cannot check whether ${abs} is git-ignored: ${(r.stderr || '').trim()}`);
}
