import fs from 'node:fs';
import path from 'node:path';
import { SkvError } from './errors.mjs';
import { writeFileAtomic } from './fsutil.mjs';
import { withLock } from './lock.mjs';
import { layout } from './paths.mjs';

export const CONFIG_VERSION = 1;
export const defaultConfig = () => ({ version: CONFIG_VERSION, settings: {}, links: {} });

/** config.json, or the default when it is missing. */
export function readConfig(home) {
  const file = layout(home).config;
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return defaultConfig();
    throw err;
  }
  try {
    const cfg = JSON.parse(text);
    cfg.links ??= {};
    return cfg;
  } catch {
    throw new SkvError('config', `${file} is not valid JSON`);
  }
}

/** Read-modify-write config.json under a lock. `fn(cfg)` mutates the config and may return a result. */
export function updateConfig(home, fn) {
  const p = layout(home);
  if (!fs.existsSync(home)) throw new SkvError('no-home', `${home} does not exist: run \`skv init\``);
  return withLock(path.join(home, 'config.lock'), () => {
    const cfg = readConfig(home);
    const result = fn(cfg);
    writeFileAtomic(p.config, `${JSON.stringify(cfg, null, 2)}\n`);
    return result;
  }, { what: 'config.json' });
}

/** File systems that ignore case by default: Windows and macOS. */
export const caseInsensitive = (platform = process.platform) => platform === 'win32' || platform === 'darwin';

const pathKey = (p, platform) => (caseInsensitive(platform) ? p.toLowerCase() : p);
export const samePath = (a, b, platform = process.platform) => pathKey(a, platform) === pathKey(b, platform);

/** Absolute, normalized folder path; symlinks resolved when the folder exists. */
export function normalizeDir(dir = '.', cwd = process.cwd()) {
  const abs = path.resolve(cwd, dir);
  try {
    return fs.realpathSync(abs);
  } catch {
    return abs;
  }
}

/** The stored link key matching `dir` (case-insensitively on Windows/macOS), or undefined. */
export function findLinkKey(links, dir, platform = process.platform) {
  return Object.keys(links).find((p) => samePath(p, dir, platform));
}

/**
 * The link that applies to `dir`: the folder itself or its nearest linked ancestor.
 * Returns { path, groups } or null.
 */
export function resolveLink(links, dir, platform = process.platform) {
  const sep = platform === 'win32' ? path.win32 : path.posix;
  for (let d = dir; ; d = sep.dirname(d)) {
    const key = findLinkKey(links, d, platform);
    if (key) return { path: key, groups: [...links[key]] };
    if (sep.dirname(d) === d) return null;
  }
}

/** Bind `groups` to `dir` (replacing any previous groups for that folder). Returns the previous groups or null. */
export function setLink(home, dir, groups) {
  return updateConfig(home, (cfg) => {
    const old = findLinkKey(cfg.links, dir);
    const previous = old ? cfg.links[old] : null;
    if (old) delete cfg.links[old];
    cfg.links[dir] = groups;
    return previous;
  });
}

/** Remove the link of `dir`. Returns { path, groups } or throws when there is none. */
export function removeLink(home, dir) {
  return updateConfig(home, (cfg) => {
    const key = findLinkKey(cfg.links, dir);
    if (!key) throw new SkvError('not-found', `no link for ${dir} (see \`skv links\`)`);
    const groups = cfg.links[key];
    delete cfg.links[key];
    return { path: key, groups };
  });
}

/** Every link: [{ path, groups, exists }], sorted by path. */
export function listLinks(home) {
  const { links } = readConfig(home);
  return Object.keys(links)
    .sort()
    .map((p) => ({ path: p, groups: [...links[p]], exists: fs.existsSync(p) }));
}

/** Groups linked to `dir` or its nearest linked ancestor: { path, groups } or a clear error. */
export function linkedGroups(home, dir) {
  const link = resolveLink(readConfig(home).links, dir);
  if (!link || !link.groups.length) {
    throw new SkvError('no-link', `no groups linked to ${dir} or its parent folders: pass a group, or link one with \`skv link <group> --path <dir>\``);
  }
  return link;
}
