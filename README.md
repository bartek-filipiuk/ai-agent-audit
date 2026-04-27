# ai-agent-audit

Read-only security audit of a local developer machine, focused on the attack surface that AI coding agents can reach.

This tool answers a single question: **"What can an AI coding agent see and do on this machine right now, and how bad would it be if one of them went off the rails?"**

It scans for credentials, tool configuration, session artifacts, and supply-chain compromise indicators that AI agents (Cursor, Claude Code, Gemini CLI, Cline, Aider, Amazon Q, and others) routinely have access to. Every finding maps to a documented incident class.

## Why this exists

AI coding agents have broad access to `$HOME` by design — that is what makes them useful. The same access turns the developer machine's credential surface into the agent's attack surface. Recent incidents share one root cause: nobody had audited what was actually reachable from the agent's working directory.

- **Nx s1ngularity (Aug 2025)** — compromised npm packages used local AI CLIs (`claude`, `gemini`, `q`) invoked with permission-bypass flags to harvest 2,349 credentials from 1,079 systems.
- **PocketOS / Railway** — production database wiped in nine seconds because an agent located a credential in an unrelated file in the working directory.
- **HiddenLayer Cursor PoC, Comment-and-Control, Clinejection, Replit incident, Gemini CLI prompt injection** — different vendors, same pattern: agent reads file, agent acts on file, blast radius equals everything the agent could reach.

The audit reports the blast radius before the next incident does.

## Platform support

Designed and tested on **Linux** (Debian/Ubuntu, Fedora, Arch) and **macOS** (Intel and Apple Silicon). Shells: `bash` and `zsh`.

The same scripts run on both platforms. Module checks adapt automatically: `launchctl` and `socketfilterfw` on macOS, `systemctl` and `ufw`/`firewalld` on Linux. No Windows support; WSL2 works as a Linux target.

## What it does

- **Ten audit modules (A–J)** covering credentials, AI tool configuration, token scope, environment separation, backups, sandboxing, supply-chain compromise indicators, browser and password-manager session state, network egress, and credential leakage in shell history and AI session transcripts.
- **Two reports per run.** `audit-report.md` is human-readable and grouped by severity. `audit-report.json` contains every finding for scripting and diffing across runs.
- **Hard guarantees.** Read-only on the host filesystem outside the output directory. No network calls. No secret values are ever written to disk or shown on screen — only paths, types, and counts. The user verifies any flagged credential manually.

## Requirements

**Required:** `bash`, and standard POSIX tools (`find`, `grep`, `stat`, `sed`).

**Optional** — modules degrade gracefully when these are missing:

| Tool | Used by | Behaviour without it |
|------|---------|----------------------|
| `jq` | post-processing examples | use `python3 -m json.tool` |
| `sqlite3` | J — Cursor chat history scan | Cursor session check skipped |
| `gh` | A.7, G.3 — GitHub token scope, s1ngularity-repo check | those checks skipped |
| `npm` | A.3, G — npm token + Nx version detection | npm-based checks skipped |
| `aws` | A.2, C — AWS profile inspection | AWS-specific checks degraded |
| `op` / `bw` | H — 1Password / Bitwarden session state | password manager checks skipped |
| `ssh-keygen` / `ssh-add` | A.1 — passphrase test, ssh-agent state | SSH passphrase check less reliable |

## Install

```bash
git clone https://github.com/bartek-filipiuk/ai-agent-audit.git
cd ai-agent-audit
chmod +x scripts/run-audit.sh scripts/aggregate.sh scripts/lib/*.sh scripts/modules/*.sh
```

No build step, no runtime dependencies, no daemon, no install of any kind beyond `chmod`.

## Usage

Full audit:

```bash
bash scripts/run-audit.sh
```

Selected modules only:

```bash
bash scripts/run-audit.sh --modules A,B,G
```

Custom output directory:

```bash
bash scripts/run-audit.sh --output ~/audits/$(date +%F)
```

Help:

```bash
bash scripts/run-audit.sh --help
```

## Modules

| ID | Domain | Key checks |
|----|--------|------------|
| **A** | Credentials | SSH keys (passphrase, perms, ssh-agent loaded), AWS / GCP / Azure / Kubernetes, npm / cargo / pypi / docker tokens, GitHub CLI and `git-credentials`, `.env` files in workspace, GPG, crypto wallets |
| **B** | AI tool config | Installed AI CLIs, dangerous flags in shell init (`--yolo`, `--dangerously-skip-permissions`), MCP configs (plaintext secrets, `npx`-launched servers), project rules files (`CLAUDE.md`, `.cursorrules`), Cursor auto-approve, Claude Code `allowedTools` |
| **C** | Token scope | GitHub token type (classic PAT vs fine-grained), AWS long-lived vs SSO, npm token count |
| **D** | Environment separation | Distinct AWS profiles, SSH host aliases, prod `DATABASE_URL` in dev workspace, `.env` in `.gitignore` |
| **E** | Backup hygiene | Backup tool presence (`restic`, `borg`, Time Machine), git remote diversity |
| **F** | Sandbox / isolation | Container / VM / WSL detection, group memberships (`docker`, `sudo`, `wheel`), sudo cache state |
| **G** | Nx-style compromise | Compromised Nx versions (20.9.0–21.8.0), `shutdown` injection in shell init, `s1ngularity-repository*` on GitHub, `/tmp/inventory.txt`, suspicious npm `postinstall` scripts |
| **H** | Browser / password manager | Browser data presence, 1Password / Bitwarden unlock state |
| **I** | Network egress | Firewall (`ufw`, `firewalld`, `socketfilterfw`), outbound firewall (Little Snitch / LuLu on macOS), `HTTP_PROXY` |
| **J** | Sessions and history | Secrets in `bash` / `zsh` / `psql` / `mysql` history, Claude Code session JSONL files (`~/.claude/projects/*/sessions/`), Cursor SQLite chat history (`state.vscdb`), Aider / Cline state |

## Output

After a run:

```
~/.ai-agent-audit/
├── audit-report.md           # human-readable, severity-grouped
├── audit-report.json         # all findings as JSON
└── findings/
    ├── A.jsonl
    ├── B.jsonl
    └── ...
```

## Severity rubric

- **CRITICAL** — directly enables a documented incident class (e.g. SSH key without passphrase plus loaded `ssh-agent`, compromised Nx version, `shutdown` injection in shell init).
- **HIGH** — significantly amplifies blast radius (long-lived AWS keys, `.env` in workspace, secrets in shell history).
- **MEDIUM** — hygiene issue (loose file permissions, single AWS profile, no backup tool).
- **LOW** — best practice deviation.
- **INFO** — context, no action needed.

## Privacy and safety guarantees

- **Read-only.** The audit never writes outside `~/.ai-agent-audit/` (or `--output`).
- **No network.** Nothing is sent anywhere.
- **No secret values.** Credential patterns are detected by regex but findings record only path, type, and count. The user verifies manually with the suggested `grep` command.
- **No auto-remediation.** Findings include remediation steps, but every fix is run by the user.

## Useful commands after a run

```bash
# Inspect raw findings:
cat ~/.ai-agent-audit/findings/A.jsonl | jq

# Count findings by severity:
jq -r .severity ~/.ai-agent-audit/findings/*.jsonl | sort | uniq -c

# All CRITICAL items:
grep -h CRITICAL ~/.ai-agent-audit/findings/*.jsonl | jq

# Re-run a single module:
bash scripts/run-audit.sh --modules G
```

## Project structure

```
ai-agent-audit/
├── README.md                          # this file
├── SKILL.md                           # Claude skill entry point
├── scripts/
│   ├── run-audit.sh                   # main orchestrator
│   ├── aggregate.sh                   # JSONL → JSON + Markdown
│   ├── lib/common.sh                  # shared helpers
│   └── modules/
│       ├── A_credentials.sh
│       ├── B_ai_tools.sh
│       ├── C_tokens.sh
│       ├── D_env_separation.sh
│       ├── E_backup.sh
│       ├── F_sandbox.sh
│       ├── G_compromise.sh
│       ├── H_browser_session.sh
│       ├── I_network.sh
│       └── J_history_sessions.sh
└── references/
    ├── incident-catalog.md            # documented incidents driving the checks
    └── remediation-guides.md          # vendor-specific fix steps
```

## Limitations

- Heuristic regex on history and session files produces false positives (e.g. example tokens inside documentation). Always verify before treating a finding as a real leak.
- Local machine only. The audit does not inspect remote servers or CI runners.
- Module H is intentionally minimal. Reading browser SQLite cookie stores would expose live session tokens, which would violate the "no secret values" guarantee.
- Module G's Nx version range is a static snapshot of the August 2025 s1ngularity attack. New supply-chain attacks require updating the list.
- Active prompt-injection attacks are not detected. The audit reports post-hoc indicators of compromise, not zero-day session tampering.

## License

MIT
