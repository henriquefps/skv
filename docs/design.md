# skv: design

`skv` (secrets keeper vault) is a local secrets manager. It keeps all the credentials
(API keys, tokens, `.env` files, signing keys) of every project in one encrypted vault in
the user's home folder, outside every repository, and gives agents and people a CLI to use
them without copying `.env` files into repos.

## Goals

- One place for every credential, outside all repos.
- Agents find and use a credential from the terminal without the value ending up in a repo,
  a commit or, ideally, the conversation transcript.
- An audit log: when a key was created, changed, removed, read or injected, and by whom.
- Encrypted at rest; a copy of `vault/` alone (backup, sync to another machine) reveals nothing.
  The key file is the only thing to guard.
- Works the same on macOS, Linux and Windows. No dependency on the macOS Keychain or any
  other OS-specific store.
- Node 20+, zero npm dependencies (only `node:crypto`, `node:fs`, ...), like `skm`.

## Non-goals (for v1)

- Protecting secrets from an agent that runs as the user: the vault prevents leaks (repo commits, backups,
  stray `.env` files, accidental reads into transcripts), it is not a sandbox. The agent read policy (Phase 3)
  is a guard against accidents, not a security boundary.
- Sync between machines, sharing with other people, a web UI. See "Later".

## Storage layout

Root: `$SKV_HOME`, default `~/.skv` (`os.homedir()`, so it works on all three OSes).
Folder mode `0700`, files `0600` (on Windows, best effort; document it).

```
~/.skv/
  key                  32 random bytes (base64), the master key; never copied with vault/
  config.json          plain JSON: version, settings, project links (no secrets)
  vault/
    <group>.enc        one encrypted file per group
  log.jsonl            audit log, one JSON object per line, never contains values
```

- **Group**: a named set of secrets, usually one service or project: `openai`, `cloudflare`,
  `openlive`. Name: lowercase `a-z0-9-`, max 64.
- **Key**: an env-var name inside a group, `[A-Z_][A-Z0-9_]*`.
- **File secrets**: binary files (e.g. an Android `.jks`) are stored in a group as base64 with
  `type: "file"` and the original file name.

Decrypted group format:

```json
{
  "version": 1,
  "group": "openai",
  "description": "OpenAI API",
  "secrets": {
    "OPENAI_API_KEY": {
      "type": "string",
      "value": "sk-...",
      "createdAt": "2026-11-05T12:00:00.000Z",
      "updatedAt": "2026-11-05T12:00:00.000Z",
      "note": "personal account",
      "history": [{ "value": "sk-old...", "replacedAt": "..." }]
    }
  }
}
```

`history` keeps the last 5 previous values so a bad rotation can be rolled back.

### Encryption

- AES-256-GCM via `node:crypto`, random 12-byte IV per write, 16-byte auth tag.
- `.enc` file = JSON envelope `{ "v": 1, "alg": "aes-256-gcm", "iv", "tag", "data" }` (base64),
  with the group name as additional authenticated data so files can't be swapped.
- Master key source, in order: `SKV_KEY` env var (base64) → unlock session (`skv unlock`, Phase 3) →
  `~/.skv/key`. A missing key is a clear error that points to `skv init`; a passphrase-protected key file
  without a session is "the vault is locked: run `skv unlock`".
- Writes are atomic (write temp file in the same folder, then rename).
- Key providers are a small interface (`load()`, `store()`) so a passphrase-derived key
  (scrypt) or OS keychains can be added later without changing the vault format.

## CLI

```
skv init                                    create ~/.skv, the key, config; idempotent
skv groups [--json]                         list groups with secret count and last change
skv ls [group] [--json]                     list key names, type, updatedAt; NEVER values
skv set <group> <KEY> [--note text]         value from stdin (pipe) or a hidden prompt;
                                            never from argv (it would land in shell history)
skv set-file <group> <KEY> <path>           store a binary/text file
skv get <group> <KEY>                       print one value (logged)
skv rm <group> <KEY> | skv rm <group> --all   (confirmation unless --yes)
skv import <group> <path/.env>              import a dotenv file (reports added/changed/unchanged)
skv export <group>[,group...] [--format dotenv|json] [-o file]
                                            write to a file (0600) or stdout; refuses to write
                                            inside a git repo unless the path is git-ignored
skv run <group>[,group...] -- <cmd> [args]  run a command with the secrets as env vars;
                                            file secrets go to a temp file (0600, removed on
                                            exit) and the var holds its path
skv log [group] [--since 7d] [--json]       audit log
skv rollback <group> <KEY>                  restore the previous value
skv link <group>[,group...] [--path dir]    bind groups to a project folder (stored in config.json)
skv link --rm [--path dir] | skv links      unlink a folder / list links
skv which [--path dir]                      the groups that apply to a folder
skv run -- <cmd> / skv export               with no group: use the groups linked to the cwd
                                            or its nearest linked ancestor
skv doctor                                  permissions, key present, files decrypt, orphan links
```

Exit codes: 0 ok, 1 error, 2 usage. `--json` on every listing command.

### Audit log

Each line: `{ "ts", "action", "group", "key", "host", "actor", "cwd" }`.

- `action`: `init|set|set-file|rm|import|export|get|run|rollback|link`.
- `actor`: `agent` when the process looks like it runs under an agent (`CLAUDECODE`,
  `CODEX_*` env vars), otherwise `user`; plus `process.env.USER`. `ORCA_*` is not a marker: Orca
  exports it in every terminal, including the user's own. `SKV_ACTOR=user|agent` overrides.
- `set` adds `"changed": true|false` and a short fingerprint (first 8 hex of
  HMAC-SHA256(master key, value)) so you can tell whether two values are the same
  without storing them. Never the value itself.

## Agent usage (shipped as `skills/skv/SKILL.md`)

1. To find a credential: `skv groups`, `skv ls <group>`. Never `cat` vault files.
2. To use it: prefer `skv run <group> -- <cmd>`, so the value never appears in the
   transcript. Use `skv get` only when the value must be pasted somewhere.
3. When the user gives a new credential: store it with `printf '%s' "..." | skv set <group> KEY`,
   not in a repo `.env`.
4. When a tool needs a `.env` file: `skv export <group> -o <path>` to a git-ignored path,
   and say where it went.
5. Never commit, echo into logs, or paste values into PRs, issues or docs.

## Migration

- `~/.openlive-keys/` (`openlive-upload.jks`, `openlive-upload.properties`) → group `openlive`.
- Scan other projects for `.env` files the user wants to centralize (on request).

## Implementation plan

Phase 1 (MVP): `init`, crypto + vault store, `set`, `set-file`, `get`, `ls`, `groups`, `rm`,
`import`, `export`, `run`, `log`, `doctor`; tests with `node --test` using a temp `SKV_HOME`;
README; `skills/skv/SKILL.md`; `npm link` installs `skv` on PATH.

Phase 2 (done): `link` / `links` / `which` + cwd resolution for `run` and `export` (nearest linked ancestor;
paths normalized with `path.resolve` + `realpath`, compared case-insensitively on Windows and macOS), `rollback`
(the current value goes into the history, so rolling back twice undoes it), `doctor` reports orphan links,
a lock file per group (`vault/<group>.lock`, `wx`, stale after 30 s, waited on for up to 5 s) around every
read-modify-write so concurrent `skv set` don't lose writes. Migration of `~/.openlive-keys` is done separately
(by hand, with `skv set-file`).

Phase 3 (done): hardening.

- **Agent read policy** (on by default). When the actor is `agent`, `skv get` is refused (exit 1, pointing to
  `skv run <group> -- <cmd>`) and `skv export` to stdout is refused; `export -o <file>` stays allowed (git-ignore
  check applies). Refusals are logged with `denied: true`. Setting `settings.agentRead: "deny" | "allow"` in
  `config.json`, changed with `skv config set agent-read allow|deny` (`allow` is refused and logged as denied when the actor is an agent; `deny` is allowed) and shown
  by `skv config`. Users are unaffected. It is a guard against accidental reads into transcripts, not a security
  boundary: an agent runs as the user and could read the key file or set `SKV_ACTOR=user`.
- **Optional passphrase** (off by default). `skv passphrase set|change|remove` (hidden prompt, or one passphrase per
  line on stdin for scripts; minimum 8 characters). The key file becomes a JSON envelope
  `{ v: 1, kdf: "scrypt", params: { N: 2^17, r: 8, p: 1, keylen: 32 }, salt (16 B), iv, tag, data }`: the master key
  wrapped with AES-256-GCM under a scrypt-derived key. The master key does not change, so the vault is not
  re-encrypted and a raw-key backup (`SKV_KEY`) keeps working. Writes are atomic.
- **Unlock session**, like `ssh-agent`. `skv unlock [--for 8h]` (`30m`, `12h`, `1d`, max 30d) checks the passphrase
  and starts a detached background process (`src/session-server.mjs`) that holds the master key only in memory;
  the key reaches it over its stdin pipe, never argv or env. It listens on `$SKV_HOME/session.sock` (0600, created
  under umask 077), or, when that path is too long for a Unix socket (~104 bytes on macOS), on
  `<tmpdir>/skv-<hash of SKV_HOME>/s.sock` in a private 0700 folder; on Windows on the named pipe
  `\\.\pipe\skv-<hash>`. Every request carries a random 256-bit token stored in `$SKV_HOME/session.json` (0600),
  compared in constant time, so processes that can't read that file can't use the socket. Protocol: one JSON line
  per connection, `{ token, op: status|key|lock }`. The session exits on expiry, `skv lock`, or SIGTERM/SIGHUP, and
  removes its files. `skv status` shows locked / unlocked / no passphrase, the expiry and the key source; `doctor`
  reports passphrase on/off, the session and stale session files. `log`, `links`, `which`, `doctor` and `status`
  work while locked. New log actions: `config`, `passphrase-set`, `passphrase-change`, `passphrase-remove`,
  `unlock`, `lock` (never passphrases or keys).

## Later
- Optional OS keychain providers (macOS Keychain, libsecret, Windows DPAPI), opt-in, never required.
- Sync to the other machines (cachyos-fps, Windows VM) over Tailscale/SSH; the `.enc` files are
  safe to copy, the key travels separately.
- Local web UI like `skm`'s.
- Expiry dates and reminders for keys that need rotation.
