import { SkvError, usage } from './errors.mjs';
import { readConfig, updateConfig } from './links.mjs';

/**
 * User settings in config.json `settings`. CLI names are kebab-case, stored names camelCase.
 *
 * agent-read (deny|allow, default deny): whether a process detected as a coding agent may print values
 * (`skv get`, `skv export` to stdout). A guard against accidental reads into agent transcripts, NOT a security
 * boundary: the agent runs as the same user and could read the key file or set SKV_ACTOR=user.
 */
export const SETTINGS = {
  'agent-read': { field: 'agentRead', values: ['deny', 'allow'], default: 'deny', describe: 'agents may print values (get, export to stdout)' },
};

export function settingFor(name) {
  const s = SETTINGS[name];
  if (!s) throw usage(`unknown setting "${name}" (known: ${Object.keys(SETTINGS).join(', ')})`);
  return s;
}

/** Effective settings with defaults: { 'agent-read': 'deny', ... }. */
export function readSettings(home) {
  const stored = readConfig(home).settings ?? {};
  return Object.fromEntries(Object.entries(SETTINGS).map(([name, s]) => [name, s.values.includes(stored[s.field]) ? stored[s.field] : s.default]));
}

export function writeSetting(home, name, value) {
  const s = settingFor(name);
  if (!s.values.includes(value)) throw usage(`${name} must be ${s.values.join(' or ')}`);
  return updateConfig(home, (cfg) => {
    cfg.settings ??= {};
    const previous = s.values.includes(cfg.settings[s.field]) ? cfg.settings[s.field] : s.default;
    cfg.settings[s.field] = value;
    return previous;
  });
}

/** 'allow' or 'deny'. An unreadable config fails closed (deny). */
export function agentReadPolicy(home) {
  try {
    return readSettings(home)['agent-read'];
  } catch {
    return 'deny';
  }
}

export const agentReadDenied = (what, hint = 'use `skv run <group> -- <cmd>` instead') =>
  new SkvError('denied', `${what} is disabled for agents so values stay out of the transcript: ${hint} (the user can change this with \`skv config set agent-read allow\`)`);

/**
 * remote-skv (per host): the command that starts skv on a remote machine for push/pull/sync, for hosts where
 * `skv` is not on the non-interactive PATH (e.g. `node ~/Projetos/skv/bin/skv.mjs`). Stored in
 * config.json `settings.remoteSkv` as { host: command }.
 */
export function readRemoteSkv(home) {
  const m = readConfig(home).settings?.remoteSkv;
  return m && typeof m === 'object' ? { ...m } : {};
}

/** Set (or, with an empty command, clear) the remote skv command of a host. Returns the previous one or null. */
export function writeRemoteSkv(home, host, command) {
  return updateConfig(home, (cfg) => {
    cfg.settings ??= {};
    const map = (cfg.settings.remoteSkv ??= {});
    const previous = map[host] ?? null;
    if (command) map[host] = command;
    else delete map[host];
    if (!Object.keys(map).length) delete cfg.settings.remoteSkv;
    return previous;
  });
}
