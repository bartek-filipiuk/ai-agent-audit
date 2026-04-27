---
name: ai-agent-audit
description: Auditing local developer machines (macOS/Linux, bash/zsh) for AI-agent-related security risks. Triggers when the user asks to audit, review, or harden a developer machine against AI coding agents (Cursor, Claude Code, Gemini CLI, Cline, Aider, etc.) — including credential exposure, AI-tool configuration risks, supply-chain compromise indicators (Nx s1ngularity-style attacks), session/memory inspection, command history credential leaks, and browser/session hygiene. Use this skill whenever the user mentions auditing their developer setup, finding what an AI agent could access, hardening their environment for safe AI use, or checking if a past supply-chain attack left artifacts on the machine.
---

# AI Agent Audit Skill

Skill for systematically auditing a local developer machine (macOS / Linux, bash/zsh) against the actual risk surface created by AI coding agents. Based on documented incidents (Nx s1ngularity, PocketOS/Railway, Replit, Gemini CLI, HiddenLayer Cursor PoC, Comment and Control, etc.) — see `references/incident-catalog.md`.

## When to use this skill

Trigger when the user asks any of:

- "Audit my machine for AI agent risks"
- "What could Cursor / Claude Code / Gemini access on my computer?"
- "Did the Nx attack affect me?"
- "Find credentials lying around in my home directory"
- "Check my AI tool config for safety"
- "What's in my Claude Code / Cursor session history?"
- Anything about hardening a dev environment for AI use, scoping tokens, or recovery after suspected compromise

## High-level approach

1. **Confirm scope with user** — full scan vs targeted module. Default to full.
2. **Run the audit** — execute `scripts/run-audit.sh`, which orchestrates 10 modules (A–J).
3. **Generate two outputs** — `audit-report.json` (machine-readable, all findings) and `audit-report.md` (human-readable with priorities and remediation).
4. **Present priority findings** — highlight CRITICAL and HIGH items first, then walk through the report.
5. **Offer remediation** — for each finding, explain *why* it matters (link to incident if relevant) and *what to do*.

## What the audit covers

| Module | Domain | Key checks |
|--------|--------|------------|
| A | Credentiale | SSH keys (passphrase + perms), cloud creds (AWS/GCP/Azure/K8s), package manager tokens, `.env` files, GPG, GitHub/GitLab CLI tokens |
| B | AI tooli config | Installed AI CLIs, dangerous flags in shell init, MCP server configs, plaintext secrets in MCP json, project rules files |
| C | Token scope | `gh auth status`, npm tokens, AWS profile types (long-lived vs SSO), token age |
| D | Separacja środowisk | Distinct dev/prod profiles, SSH host aliases, current workspace `.env` analysis, `.gitignore` hygiene |
| E | Backup hygiene | git remotes diversity, presence of off-site backup (TimeMachine/restic/borg), backup config |
| F | Sandbox / isolation | Devcontainer/WSL/VM detection, ssh-agent loaded keys, group memberships (docker/sudo/wheel), sudo cache state |
| G | Detekcja Nx-style kompromitacji | `npm ls nx` for vulnerable versions, shell init files for `shutdown` injections, `/tmp/inventory.txt`, `s1ngularity-repository*` artifacts, `.zshrc/.bashrc` git diff vs known-good |
| H | Browser / session hygiene | Active browser logins (heuristic), password manager session state (1Password CLI, Bitwarden) |
| I | Network egress | Firewall present, DNS resolver config, HTTP(S)_PROXY env vars |
| J | Historia + AI sessions | Shell history credential leaks (heuristic regex), Claude Code sessions (`~/.claude/projects/*/sessions/*.jsonl`), Cursor SQLite chat history (`state.vscdb`), secrets in past prompts |

## Step-by-step instructions

### Step 1 — Confirm scope

Before running, ask the user:

- Full scan or specific modules?
- Should the audit include reading session history content for credential patterns? (this is the most invasive part — confirm explicitly)
- Are they OK with the audit creating files in `~/.ai-agent-audit/` ?

If the user just says "audit my machine" — assume full scan but explicitly tell them what will be read before proceeding.

### Step 2 — Run the audit

Execute the orchestrator script:

```bash
bash scripts/run-audit.sh
```

The script:
- Detects OS (Darwin / Linux), shell, available tools
- Runs each module in order (A through J)
- Writes raw findings to `~/.ai-agent-audit/findings/<module>.json`
- Aggregates into `~/.ai-agent-audit/audit-report.json` and `~/.ai-agent-audit/audit-report.md`

If the user wants only specific modules: `bash scripts/run-audit.sh --modules A,B,G`

### Step 3 — Read the findings and present

After the script finishes, read both outputs. Then summarize for the user:

1. **Headline counts** — "Found 4 CRITICAL, 11 HIGH, 23 MEDIUM, 9 LOW issues"
2. **Top 3 CRITICAL findings** — full detail, why-it-matters, what-to-do
3. **Pattern detection** — if multiple findings point to the same root cause (e.g. "all your tokens are long-lived classic PATs"), surface that as a meta-finding
4. **Offer to present full report or focus area**

### Step 4 — Offer remediation

Each finding in the report has a `remediation` field. For HIGH/CRITICAL items, walk through fixes step-by-step. For SSH passphrase issues, offer to generate the right `ssh-keygen -p` commands. For token rotation, link to the right vendor docs.

Do NOT auto-execute remediation without explicit user confirmation per item — some fixes (rotating tokens, deleting files) are irreversible.

## Severity rubric

- **CRITICAL** — would directly enable the type of incident documented in the catalog (e.g. SSH key without passphrase + ssh-agent loaded + agent has shell access)
- **HIGH** — significantly amplifies blast radius (e.g. plaintext secrets in `~/.npmrc` with publish rights)
- **MEDIUM** — hygiene issue, fixable but not immediate threat (e.g. stale token from 2 years ago)
- **LOW** — informational / best practice

## Important notes

- **The skill never modifies files or sends data anywhere.** Read-only audit. All output stays in `~/.ai-agent-audit/`.
- **It does not extract or display actual credential values.** Findings reference paths and types, never contents (e.g. "AWS access key found at `~/.aws/credentials`, profile `prod`" — never the key itself).
- **Some checks require optional tools** (`jq`, `sqlite3`, `gh`). The skill detects what's available and skips gracefully.
- **Heuristic regex on session/history files** is opt-in. The user must explicitly confirm before module J runs the credential-pattern scan on chat histories.

## Files in this skill

- `SKILL.md` — this file
- `scripts/run-audit.sh` — main orchestrator
- `scripts/modules/*.sh` — one script per module (A–J)
- `scripts/lib/common.sh` — shared helpers (severity, JSON output, OS detection)
- `scripts/aggregate.sh` — combines module outputs into final reports
- `references/incident-catalog.md` — incidents driving each check (for context when explaining findings)
- `references/remediation-guides.md` — vendor-specific fix steps (rotate AWS, scope GH tokens, etc.)
