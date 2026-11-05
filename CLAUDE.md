# skv

Local, cross-platform secrets manager with a CLI (`skv`). Design and plan: `docs/design.md`.

- Node 20+, ES modules (`.mjs`), zero npm dependencies. Same style as `skm` (skills-manager):
  `bin/skv.mjs` entry, logic in `src/`, tests in `test/*.test.mjs` with `node --test`.
- Must work on macOS, Linux and Windows: no OS keychain, no shell-specific code, use `node:path`
  and `os.homedir()`.
- Never print, log or commit a secret value. Tests use a temporary `SKV_HOME`, never `~/.skv`.
- Secrets never come from argv (shell history): stdin or a hidden prompt.
