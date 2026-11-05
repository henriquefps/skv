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

## Rules

1. **Find a credential by name, never by reading files.** `skv groups`, then `skv ls <group>` (add `--json` to parse).
   These never show values. Never `cat`, copy or open anything under `~/.skv`.
2. **Use it through `skv run`** so the value never appears in the transcript:
   ```
   skv run openai -- node scripts/eval.mjs
   skv run cloudflare,openai -- npm run deploy
   ```
   Secrets become env vars of that one command. File secrets (type `file`) become a private temp file, removed when
   the command ends, and the variable holds its path. Use `skv get <group> <KEY>` only when the value really must be
   pasted somewhere, and never echo it back to the user.
3. **Store new credentials with `skv set` via stdin**, never in a repo `.env` and never as an argument:
   ```
   printf '%s' "$VALUE" | skv set <group> <KEY> --note "where it came from"
   skv set-file <group> <KEY> path/to/upload.jks
   skv import <group> path/to/.env        # adopt an existing dotenv file, then offer to delete it
   ```
   Pick an existing group when one fits (`skv groups`); otherwise a short lowercase name (`a-z0-9-`).
4. **When a tool insists on a `.env` file:** `skv export <group> -o <path>` to a git-ignored path (skv refuses
   any other path inside a git repo), and tell the user where the file went so they can delete it later.
5. **Never** commit values, write them to logs, or paste them into PRs, issues, docs or chat. Do not print
   `skv export` to stdout unless the user asks.

## Commands

| Command | Use |
| --- | --- |
| `skv groups [--json]` | groups with secret count and last change |
| `skv ls [group] [--json]` | key names, type, note, last change (no values) |
| `skv run <group>[,group...] -- <cmd> [args]` | run a command with the secrets as env vars; forwards its exit code |
| `skv set <group> <KEY> [--note t] [--desc t]` | store a value from stdin (or a hidden prompt for the user) |
| `skv set-file <group> <KEY> <path>` | store a file |
| `skv get <group> <KEY>` | print one value (logged) |
| `skv import <group> <file.env>` | import a dotenv file; reports added / changed / unchanged |
| `skv export <group>[,group...] [--format dotenv\|json] -o <file>` | write a git-ignored dotenv/JSON file (0600) |
| `skv rm <group> <KEY>` / `skv rm <group> --all` | delete; asks for confirmation (do not pass `--yes` unless the user agreed) |
| `skv log [group] [--since 7d] [--json]` | audit log: who read, injected or changed what (never values) |
| `skv doctor` | permissions, key present, every group decrypts |

Every read, injection and change is written to the audit log with `actor: agent` when run by you. Exit codes:
0 ok, 1 error, 2 usage; `skv run` returns the command's own exit code.
