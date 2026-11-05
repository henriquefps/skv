---
name: skv
description: Use when a task needs an API key, token, password, .env file or signing file (e.g. an Android .jks), when the user gives you a new credential to keep, or asks where a secret is stored. Finds and uses credentials from the local encrypted vault with the skv CLI, without putting values in repos or the transcript.
---

# skv: local secrets vault

`skv` keeps every credential of every project in one encrypted vault in the user's home (`~/.skv`), outside all
repositories. Secrets live in **groups** (`openai`, `cloudflare`, `openlive`), each holding **keys** named like env
vars (`OPENAI_API_KEY`).

## Prerequisite

Run `skv --help` first. If it is not found, say so: `skv` must be on PATH (`npm link` in the skv repo). If a command
says to run `skv init`, ask the user before running it: it creates a new master key.

**If a command says "the vault is locked: run `skv unlock`", stop and ask the user to run `skv unlock` in their own
terminal** (it asks for their passphrase). Never ask for the passphrase, never try to unlock it yourself, and don't
look for the key some other way. `skv status` tells you whether the vault is locked.

## Rules

1. **Find a credential by name, never by reading files.** `skv groups`, then `skv ls <group>` (add `--json` to parse).
   These never show values. Never `cat`, copy or open anything under `~/.skv`.
2. **Use it through `skv run`** so the value never appears in the transcript. Inside a project folder, first run
   `skv which`: if it prints groups, the folder is linked and you can (and should) omit the group:
   ```
   skv which                         # e.g. "openai,cloudflare  (linked at /path/to/project)"
   skv run -- npm run deploy         # uses the linked groups, from any subfolder
   skv run openai -- node scripts/eval.mjs
   skv run cloudflare,openai -- npm run deploy
   ```
   Secrets become env vars of that one command. File secrets (type `file`) become a private temp file, removed when
   the command ends, and the variable holds its path.
3. **`skv get` and `skv export` to stdout are refused for you** (the default agent read policy; the refusal is
   logged). Never try to get around it: don't set `SKV_ACTOR`, don't read `~/.skv`, don't print the variables
   inside `skv run`, and don't run `skv config set agent-read allow` (it is refused for agents anyway; only the
   user decides). Most tools read their env var directly. To hand a secret to a tool that wants it on stdin, pipe
   it inside `skv run`, so the value only travels between processes:
   ```
   skv run <group> -- sh -c 'printf %s "$KEY" | tool login --password-stdin'
   ```
   If a value really must be shown or pasted somewhere by hand, ask the user to run `skv get` themselves.
4. **Store new credentials with `skv set` via stdin**, never in a repo `.env` and never as an argument:
   ```
   printf '%s' "$VALUE" | skv set <group> <KEY> --note "where it came from"
   skv set-file <group> <KEY> path/to/upload.jks
   skv import <group> path/to/.env        # adopt an existing dotenv file, then offer to delete it
   ```
   Pick an existing group when one fits (`skv groups`); otherwise a short lowercase name (`a-z0-9-`).
5. **When a tool insists on a `.env` file:** `skv export <group> -o <path>` to a git-ignored path (skv refuses
   any other path inside a git repo), and tell the user where the file went so they can delete it later.
6. **Linking a project** (`skv link <group>[,group...] --path <dir>`) changes the user's config: do it when the
   user asks or agrees. `skv rollback <group> <KEY>` restores the previous value after a bad rotation; it needs the
   user's confirmation (do not pass `--yes` unless they agreed).
7. **Never** commit values, write them to logs, or paste them into PRs, issues, docs or chat.
8. **Passphrase and sessions are the user's.** Don't run `skv passphrase ...`, `skv unlock` or `skv lock` unless the
   user asks you to.

## Commands

| Command | Use |
| --- | --- |
| `skv groups [--json]` | groups with secret count and last change |
| `skv ls [group] [--json]` | key names, type, note, last change (no values) |
| `skv which [--path dir] [--json]` | groups linked to this folder (or its nearest linked parent) |
| `skv run [group[,group...]] -- <cmd> [args]` | run a command with the secrets as env vars (no group: the linked ones); forwards its exit code |
| `skv set <group> <KEY> [--note t] [--desc t]` | store a value from stdin (or a hidden prompt for the user) |
| `skv set-file <group> <KEY> <path>` | store a file |
| `skv get <group> <KEY>` | print one value (logged); refused for agents by default: use `skv run` |
| `skv import <group> <file.env>` | import a dotenv file; reports added / changed / unchanged |
| `skv export [group[,group...]] [--format dotenv\|json] -o <file>` | write a git-ignored dotenv/JSON file (0600); no group: the linked ones |
| `skv link <group>[,group...] [--path dir]` / `skv link --rm [--path dir]` / `skv links` | link groups to a project folder, unlink, list |
| `skv rollback <group> <KEY>` | restore the previous value (again to undo); asks for confirmation |
| `skv rm <group> <KEY>` / `skv rm <group> --all` | delete; asks for confirmation (do not pass `--yes` unless the user agreed) |
| `skv log [group] [--since 7d] [--json]` | audit log: who read, injected or changed what (never values) |
| `skv doctor` | permissions, key present, every group decrypts, orphan links, passphrase and session |
| `skv status [--json]` | locked / unlocked / no passphrase, expiry, key source |

Every read, injection and change is written to the audit log with `actor: agent` when run by you. Exit codes:
0 ok, 1 error, 2 usage; `skv run` returns the command's own exit code.
