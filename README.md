# skv

Secrets keeper vault: one encrypted, local place for the credentials of all your projects, outside every
repository, with a CLI for people and coding agents and an audit log.

- AES-256-GCM, one encrypted file per group, a single master key you guard.
- `skv run <group> -- <cmd>` injects secrets as env vars, so values stay out of repos, `.env` files and agent
  transcripts. Link groups to a project folder once and `skv run -- <cmd>` picks them up from anywhere inside it.
- Values are never read from argv (shell history), never printed by listings, never written to the log.
- Agents can't print values by default (`skv get` and `skv export` to stdout are refused for them; `skv run` works).
- Optional passphrase on the key file, with an `ssh-agent`-like unlock session (`skv unlock` / `skv lock`).
- macOS, Linux and Windows. Node 20+, zero npm dependencies, no OS keychain.

Design and roadmap: [docs/design.md](docs/design.md). Agent rules: [skills/skv/SKILL.md](skills/skv/SKILL.md).

## Install

```sh
git clone https://github.com/henriquefps/skv.git
cd skv
npm link          # puts `skv` on PATH
skv init          # creates ~/.skv, the master key and config.json
```

Back up `~/.skv/key` somewhere safe and separate from `~/.skv/vault/` (a password manager, a USB stick). Without it
the vault cannot be decrypted; with it, anyone who also has a copy of `vault/` can read everything.

To give agents the usage rules, link or copy `skills/skv` into your skills folder (e.g. `~/.agents/skills/skv`).

## Quick start

```sh
# store a value: from stdin, or type it at the hidden prompt
printf '%s' "$OPENAI_API_KEY" | skv set openai OPENAI_API_KEY --note "personal account"
skv set cloudflare CLOUDFLARE_API_TOKEN            # prompts, nothing echoed

# store a file (binary is fine)
skv set-file openlive UPLOAD_JKS ~/keys/openlive-upload.jks

# adopt an existing .env file
skv import myapp ./.env

# see what is there (names only, never values)
skv groups
skv ls openai

# use it
skv run openai -- node scripts/eval.mjs
skv run openai,cloudflare -- npm run deploy

# link groups to a project once, then skip the group name anywhere inside it
skv link openai,cloudflare --path ~/code/myapp
cd ~/code/myapp/scripts && skv run -- npm run deploy
skv which                    # openai,cloudflare  (linked at /home/me/code/myapp)

# undo a bad rotation
skv rollback openai OPENAI_API_KEY

# who used what
skv log --since 7d

# optional: protect the key file with a passphrase, then unlock for a working day
skv passphrase set           # hidden prompt, twice
skv unlock --for 8h          # background session holds the key in memory
skv status                   # unlocked, expires ..., key source: unlock session
skv lock
```

## Commands

| Command | What it does |
| --- | --- |
| `skv init` | Create `$SKV_HOME` (default `~/.skv`), the key and `config.json`. Idempotent: never replaces an existing key, and refuses to create a new key when encrypted groups exist without one. |
| `skv groups [--json]` | Groups with secret count, last change and description. |
| `skv ls [group] [--json]` | Key names, type, note and last change. Never values. |
| `skv set <group> <KEY> [--note t] [--desc t]` | Store a value read from stdin (one trailing newline is stripped) or a hidden TTY prompt. A value on the command line is refused. `--desc` sets the group description. Prints added/changed/unchanged and a fingerprint. |
| `skv set-file <group> <KEY> <path> [--note t]` | Store a file's bytes (base64 inside the vault) with its file name. |
| `skv get <group> <KEY>` | Print one value (no trailing newline when piped; raw bytes for file secrets). Logged. Refused for agents unless `agent-read` is `allow` (see below). |
| `skv rm <group> <KEY>` / `skv rm <group> --all` | Delete one key or a whole group. Asks for confirmation; `--yes`/`-y` skips it (required without a TTY). |
| `skv import <group> <file>` | Import a dotenv file: `# comments`, `export KEY=`, unquoted values with ` # inline comments`, `'single'` (literal), `"double"` (escapes `\n \r \t \\ \" \$`) and multiline quoted values. Reports added / changed / unchanged. `--json` for structured output. |
| `skv rollback <group> <KEY> [--yes]` | Restore the most recent previous value. The current value goes into the history, so a second rollback undoes the first. Asks for confirmation (`--yes`/`-y` without a TTY); an error when the key has no history. Logged with the old and new fingerprints. |
| `skv export [group[,group...]] [--format dotenv\|json] [-o file]` | Write the secrets to stdout or to a file (mode 0600, atomic). Inside a git repo the path must be git-ignored (checked with `git check-ignore`), otherwise skv refuses. File secrets are skipped (use `run` or `get`). Agents may only use `-o` unless `agent-read` is `allow`. |
| `skv run [group[,group...]] -- <cmd> [args...]` | Run a command with the secrets added to its environment. File secrets are written to a private temp folder (0700, files 0600) and the variable holds the path; the folder is removed when the command ends. Signals (Ctrl-C, SIGTERM, ...) are forwarded; the command's exit code is returned. |
| `skv link <group>[,group...] [--path dir]` | Link groups to a project folder (default: the current folder), stored in `config.json`. Replaces the folder's previous groups. Every group must exist. |
| `skv link --rm [--path dir]` | Remove a folder's link (works for folders that no longer exist). |
| `skv links [--json]` | Linked folders and their groups; missing folders are marked. |
| `skv which [--path dir] [--json]` | The groups that apply to a folder: its own link or the nearest linked parent folder. Exit 1 when none. |
| `skv log [group] [--since 30m\|12h\|7d\|2w\|date] [--json]` | Audit log. |
| `skv doctor [--json]` | Checks folder/file permissions, key present and valid, config, every group decrypts, leftover temp and stale lock files, links whose folder or groups are gone (warnings), passphrase on/off, the unlock session and stale session files. While locked, the decrypt checks are skipped with a warning. Exit 1 on errors. |
| `skv config [--json]` | Show the settings (`agent-read`). |
| `skv config set agent-read allow\|deny` | Let agents print values (`allow`) or not (`deny`, the default). Refused when run by an agent. |
| `skv passphrase set` | Protect the key file with a passphrase (hidden prompt twice, or one line on stdin; at least 8 characters). The master key and the vault don't change. |
| `skv passphrase change` | Current passphrase, then the new one (stdin: two lines). A running session keeps working. |
| `skv passphrase remove` | After the current passphrase, write the raw key back to the key file and end any session. |
| `skv unlock [--for 8h]` | Ask for the passphrase and start a background session that holds the key in memory for `30m`, `8h` (default), `12h`, `1d`... (max 30d). Replaces a running session. |
| `skv lock` | End the session now (also cleans up stale session files). |
| `skv status [--json]` | `locked`, `unlocked` (with expiry and session pid) or `no passphrase`, the key source in use, and `agent-read`. Works while locked. |

`run` and `export` without a group use the groups linked to the current folder or its nearest linked parent, and fail
with a clear error when there is none. Link paths are absolute and normalized (symlinks resolved); they are compared
case-insensitively on Windows and macOS.

The same key name in two groups passed to `run` or `export` is an error (which one should win is ambiguous).

Exit codes: `0` ok, `1` error, `2` usage. `skv run` returns the command's exit code, `127` when the command can't be
found, and `128 + n` (or the same signal) when it was killed by a signal.

Environment:

- `SKV_HOME`: vault folder (default `~/.skv`).
- `SKV_KEY`: base64 master key; takes precedence over the unlock session and `$SKV_HOME/key` (handy on CI or to keep
  the key off disk; also opens a passphrase-protected vault).
- `SKV_ACTOR=user|agent`: override the actor detection (log and agent read policy).
- `NO_COLOR`: disable colors.

## Storage

```
~/.skv/
  key            32 random bytes, base64: the master key (or, with a passphrase, a JSON envelope wrapping it)
  config.json    version, settings and folder links (no secrets)
  session.json   only while unlocked: session pid, socket path, expiry and its access token (0600)
  session.sock   only while unlocked (POSIX): the session socket (0600)
  vault/
    <group>.enc  one encrypted file per group
    <group>.lock present only while a write to that group is in progress
  log.jsonl      audit log, one JSON object per line
```

Each `.enc` file is `{ "v": 1, "alg": "aes-256-gcm", "iv", "tag", "data" }` (base64), a random 12-byte IV per write,
and the group name as additional authenticated data, so a file renamed to another group fails to decrypt. Writes
go to a temp file in the same folder and are renamed into place. Each key keeps its last 5 previous values,
which `skv rollback` restores.

Audit log lines: `{ ts, action, group, key, host, actor, user, cwd, ... }`. `actor` is `agent` when the process runs
under a coding agent (`CLAUDECODE` or `CODEX_*` env vars), otherwise `user` (`ORCA_*` is ignored: Orca sets it in
every terminal, including yours; `SKV_ACTOR` overrides). `set` and `import` add
`changed` and a `fingerprint` (first 8 hex of HMAC-SHA256(master key, value)) to tell whether two values are the
same. `run` and `export` record the key names and the command's base name (never its arguments). Values are never
logged.

## Agent read policy

When skv runs under a coding agent (actor `agent`: `CLAUDECODE` or `CODEX_*` in the environment, or
`SKV_ACTOR=agent`), it refuses to print values: `skv get` exits 1 with a pointer to `skv run <group> -- <cmd>`, and
`skv export` to stdout exits 1 (`export -o <git-ignored file>` still works). Each refusal is logged (`denied: true`,
never the value). `skv run` is unaffected, and so are users.

`skv config set agent-read allow` turns the guard off (`deny` turns it back on); an agent can't change it.

This is a guard against **accidental** reads ending up in an agent transcript, **not a security boundary**: the agent
runs as your user, so it could read the key file, set `SKV_ACTOR=user`, or print the variables inside `skv run`.
Its value is that a well-behaved agent following the skill never prints a value by mistake.

## Passphrase and unlock session (optional)

Off by default; nothing changes unless you run `skv passphrase set`. Then `$SKV_HOME/key` holds the master key
encrypted with AES-256-GCM under a key derived from your passphrase with scrypt (N=2^17, r=8, p=1, random 16-byte
salt; the parameters are stored in the file). The master key itself is unchanged, so the vault is not re-encrypted
and a raw-key backup keeps working with `SKV_KEY=...`. Back up the raw key **before** setting a passphrase (or keep
the passphrase safe): forgetting the passphrase without a backup loses the vault.

While locked, commands that need the key fail with "the vault is locked: run `skv unlock`"; `log`, `links`,
`which`, `doctor` and `status` still work. `skv unlock` starts a detached background process that holds the key
only in memory until it expires or you run `skv lock`. It listens on `$SKV_HOME/session.sock` (or, when that path
is too long for a Unix socket, a private 0700 folder in the OS temp dir; on Windows a named pipe
`\\.\pipe\skv-<hash>`), and every request must carry a random token kept in `$SKV_HOME/session.json` (0600).
Key lookup order: `SKV_KEY` → unlock session → plain key file.

For scripts, passphrases can be piped on stdin, one per line (`printf '%s\n' "$PASS" | skv unlock`).

## Security model and its limits

What skv protects against:

- Secrets in repos, commits, stray `.env` files and project backups: they live in one folder outside every repo.
- A copy of `vault/` alone (a backup, a synced folder): without the key it reveals nothing, and tampering or
  swapping files is detected.
- Secrets in shell history: `set` never takes a value on the command line.
- Secrets in agent transcripts by accident: agents get `skv run`, while `skv get` and `export` to stdout are refused
  for them by default.
- With a passphrase: a copy of the whole `~/.skv` folder (key file included) without the passphrase, and anyone
  using your account while the vault is locked.

What it does not protect against:

- **Anyone who can read the key file (without a passphrase).** The key sits next to the vault, protected only by
  file permissions (0600). Malware or another process running as your user can read it, and anyone with your user
  account can run `skv get`. Set a passphrase to close this while locked.
- **Processes of your user while unlocked.** The session token sits in `session.json` (0600): anything running as
  you can read it and ask the session for the key, exactly like an `ssh-agent` socket. Lock when you don't need it;
  sessions expire on their own. A passphrase is also only as strong as you make it (scrypt slows guessing, it doesn't
  stop it).
- **An agent determined to read values.** The agent read policy stops accidents, not an agent running as you:
  skv is a leak-prevention tool and an audit trail, not a sandbox.
- **Child processes of `skv run`.** They see the values in their environment, and so can anything they start.
  On Linux, other processes of the same user can read `/proc/<pid>/environ`.
- **Temp files after a hard kill.** File secrets for `run` are removed when the command ends or skv gets a signal,
  but not if skv itself is killed with SIGKILL or the machine loses power (they stay in the OS temp folder, mode 0600).
- **Windows permissions.** Modes 0700/0600 are best effort; Windows ignores them and the vault relies on the ACLs of
  your user profile folder. Keep `SKV_HOME` inside your profile.
- **Concurrent writes.** Writes to a group (`set`, `set-file`, `import`, `rm`, `rollback`) hold a lock file
  (`vault/<group>.lock`, created exclusively) around read-modify-write, so concurrent `skv set` on the same group
  don't lose each other's keys; a writer waits up to 5 s for the lock. A lock left by a crashed process goes stale
  after 30 s and is taken over (`skv doctor` reports it). The lock is advisory: it only coordinates skv processes,
  and on network or synced folders exclusive creation may not be reliable. Setting the same key at the same moment
  still means the last one wins (the other value is in its history).

## Development

```sh
npm test   # node --test, every test uses a temporary SKV_HOME
```
