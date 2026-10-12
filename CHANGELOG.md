# Changelog

## 2026-10-12 — open source release

- **Landing page and fix-it guide** at https://local-security.devince.dev (Polish and English).
- **The network statement is now accurate.** README, SKILL.md and the usage guide used to say "no network calls". The audit sends nothing to the author or any third party, but your own logged-in `gh`, `npm` and `op` CLIs do talk to GitHub, npm and 1Password about your account (token scopes, repository names, token count, session state). Leave modules A, C, G and H out of `--modules` to skip them.
- **SECURITY.md** describes how to report a weakness in the tool privately.

## 2026-10 — hardening round

What changed for someone running the tool. Details per change are in the commit messages and in `docs/improvement-plan-2026-10.md`.

### Breaking

- **bash 4.4 or newer is required.** On macOS install it with `brew install bash` and run `"$(brew --prefix)/bin/bash" scripts/run-audit.sh`. The scripts exit with that hint under an older bash.
- **`--output` now isolates the run.** Before, every module and the report generator ignored it and wrote to `~/.ai-agent-audit`, and a `--modules` run mixed in stale findings from earlier runs.
- **`purge-secrets.sh --purge` redacts in place** (`[REDACTED:<fingerprint>]`) instead of deleting lines, and keeps backups in `~/.ai-agent-audit/purge-backups/<timestamp>/` instead of `<file>.bak.<ts>` next to the original. `--delete-lines` restores the old behaviour, `--no-backup` skips backups.
- **Scores are not comparable with earlier runs.** Project roots now come from where your agents actually ran, so the audit sees far more of the machine, and several dead checks now fire. On the author's machine the old run had looked at one directory.

### Safety of the tool itself

- No secret value can reach a report: every finding passes a redactor, and MCP launch args are no longer copied into evidence.
- Text copied from files an attacker could control is truncated and labelled `[untrusted content]`; SKILL.md tells the agent to treat it as data.
- Raw matches live only in a private temp directory that is removed on exit or interrupt (an interrupt used to leave plaintext secrets in `/tmp`).
- Reports are written with mode 700/600.
- `audit-report.json` stays valid with control characters in evidence; no more GNU-only `sed` in the escaper.

### Detection

- Fixed checks that could never fire: compromised npm versions in project manifests, Claude Code permission settings (current `permissions` schema), MCP servers in project scope, npm token count, `ufw` state, macOS TCC, Time Machine encryption, `com.apple.*` LaunchAgent masquerade, GitHub repos beyond the first 30.
- New coverage: resolved versions in `node_modules` and `package-lock.json`, Shai-Hulud indicators, Codex and Gemini CLI sessions and MCP configs, Claude Code file-history and shell snapshots, Cline's real storage path, `.cursor/mcp.json` / `.vscode/mcp.json`, plugin hooks, `.claude/agents` and `.claude/commands`, instructions hidden in HTML comments, `.netrc`, `.pgpass`, Terraform Cloud, Vault and GitLab CLI tokens, passwordless sudo, secrets passed as `--api-key` flags, Context7 keys.
- Fewer false positives: comments mentioning `halt`, `products_dev` as "prod", `/.env` gitignore entries, emoji joiners as hidden characters, "You are now ready", "never skip code review", "never run --force without asking", plain "Always allow" lists, plugin-cache refreshes as new skills, and token-like fragments inside base64 blobs.
- A key found in several files counts once in the headline and the score.
- New `X.roots` finding lists which project roots were scanned; `AUDIT_DEV_PATHS` overrides them. New `--skip-sessions` leaves out module J.

### Reports and docs

- Score formula, grade colours and the status badge agree with each other and with the docs (README and SKILL.md had an outdated formula).
- SKILL.md, README and the usage guide describe the 15 modules as they are now.

### Development

- Test suite (`bash tests/run.sh`) that runs against a fake `HOME`, and CI with shellcheck on Ubuntu and macOS.
