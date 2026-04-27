# ai-agent-audit

Read-only security audit of a local developer machine, focused on the attack surface that AI coding agents can reach.

This tool answers a single question: **"What can an AI coding agent see and do on this machine right now, and how bad would it be if one of them went off the rails?"**

It scans for credentials, tool configuration, hooks, MCP servers, agent skills, IDE extensions, session artifacts, and supply-chain compromise indicators that AI agents (Cursor, Claude Code, Gemini CLI, Cline, Aider, Codex, Windsurf, Amazon Q, and others) routinely have access to. Every finding maps to a documented incident class.

## TL;DR

Read-only scan of `$HOME` for everything an AI coding agent can reach: SSH keys, cloud creds, npm/pip tokens, MCP server configs, AI hooks, repo-level `.claude/.cursor/` configs, agent skills, IDE extensions, plus credential leakage in shell history and session JSONL/SQLite. Outputs a security score (0–100) and five reports — Markdown, JSON, classified secrets inventory with redacted fingerprints, prioritised action plan, and a cyberpunk-themed HTML report that auto-opens in your browser. No network, no auto-remediation, no raw secret values written anywhere.

## Quick start

**Install the skill globally** (works from any project, every Claude Code session):

```bash
git clone https://github.com/bartek-filipiuk/ai-agent-audit.git ~/.claude/skills/ai-agent-audit
chmod +x ~/.claude/skills/ai-agent-audit/scripts/run-audit.sh \
         ~/.claude/skills/ai-agent-audit/scripts/aggregate.sh \
         ~/.claude/skills/ai-agent-audit/scripts/lib/*.sh \
         ~/.claude/skills/ai-agent-audit/scripts/modules/*.sh
```

The `SKILL.md` at the repo root is what Claude Code auto-discovers.

**Run directly without an agent:**

```bash
bash ~/.claude/skills/ai-agent-audit/scripts/run-audit.sh
# HTML report auto-opens in your browser at the end.
```

**Or — let Claude Code handle it.** Drop one of these prompts into any session:

> Run the ai-agent-audit skill — full scan, then open the HTML report and summarise the top 3 critical findings plus what to rotate first.

> Audit my dev machine for AI agent risks. Use the ai-agent-audit skill, run all modules, then walk me through the action plan from highest priority down.

> Use the ai-agent-audit skill to scan this machine, focusing on Nx-style supply-chain indicators (module G) and the secrets inventory. Tell me which keys to rotate today.

Claude reads `SKILL.md`, runs `bash scripts/run-audit.sh`, parses the four output files (`audit-report.md`, `audit-report.json`, `secrets-inventory.md`, `action-plan.md`), and summarises with severity-ordered recommendations. The HTML report opens automatically in your default browser unless you pass `--no-open`.

**One-line score check** (after a run):

```bash
jq -r '"\(.score)/100 [\(.grade) — \(.grade_label)]   crit:\(.summary.critical) high:\(.summary.high) secrets:\(.summary.secrets_distinct)"' ~/.ai-agent-audit/audit-report.json
```

**Purge detected secrets from history / sessions** (separate utility, dry-run by default):

```bash
# Dry-run — shows what would be removed, makes no changes
bash scripts/purge-secrets.sh

# Actually delete (creates .bak.<TIMESTAMP> backups before each modification)
bash scripts/purge-secrets.sh --purge

# Also wipe Cursor SQLite chat storage (opt-in)
bash scripts/purge-secrets.sh --purge --include-cursor
```

The purge script removes lines containing real credentials from `~/.bash_history`, `~/.claude/history.jsonl`, every `~/.claude/projects/*/sessions/*.jsonl`, and Cline state files (`~/.config/Code/User/globalStorage/*cline*/tasks/*/`). It uses the same pattern set as the audit and excludes local docker / loopback database URLs from purge by default (since `postgres://user:pass@localhost/...` is not a real leak). Run rotation in your provider UIs **before** purge — deletion of a leaked-key entry doesn't un-leak the key, only removes the trail.

## Why this exists

AI coding agents have broad access to `$HOME` by design — that is what makes them useful. The same access turns the developer machine's credential surface into the agent's attack surface. Documented incidents share one root cause: nobody had audited what was actually reachable from the agent's working directory.

- **Nx s1ngularity (August 2025)** — compromised npm packages used local AI CLIs (`claude`, `gemini`, `q`) invoked with permission-bypass flags to harvest 2,349 credentials from 1,079 systems.
- **PocketOS / Railway** — production database wiped in nine seconds because an agent located a credential in an unrelated file in the working directory.
- **MCP design flaw (April 2026)** — a single systemic vulnerability in Anthropic's MCP SDK exposed roughly 200,000 servers to RCE; nine of eleven public MCP marketplaces were successfully poisoned with a malicious trial balloon.
- **axios npm campaign (March 2026)** — `axios@1.14.1` and `axios@0.30.4` published as a malicious dependency cascade during the Claude Code source-code leak window; pulled a Remote Access Trojan into anyone who installed Claude Code or its updates between 00:21 and 03:29 UTC on 31 March.
- **Bitwarden CLI 2026.4.0** — shipped with a 10 MB obfuscated payload specifically hunting authenticated state for Claude Code, Cursor, Codex CLI, Aider, Kiro, and Gemini CLI.
- **ToxicSkills (Snyk, February 2026)** — 36 % of agent skills on the ClawHub marketplace contained prompt-injection payloads; ClawHub publishing requires only a `SKILL.md` file and a one-week-old GitHub account.
- **prettier-vscode-plus (November 2025)** — VS Code extension typosquatting Prettier deployed the Anivia loader → OctoRAT chain.
- **CVE-2025-59536 / CVE-2026-21852** — RCE through repository-level configuration files (`.claude/`, `.cursor/`, hooks, MCP entries) that AI agents auto-load when run inside an untrusted clone.
- **Sapphire Sleet (April 2026)** — macOS campaign manipulating `TCC.db` to grant `AppleEvents` permissions to `osascript` for silent, persistent data exfiltration.
- **HiddenLayer Cursor PoC, Comment-and-Control, Clinejection, Replit incident, Gemini CLI prompt injection** — different vendors, same pattern: agent reads file, agent acts on file, blast radius equals everything the agent could reach.

The audit reports the blast radius before the next incident does.

## Platform support

Designed and tested on **Linux** (Debian/Ubuntu, Fedora, Arch) and **macOS** (Intel and Apple Silicon). Shells: `bash` and `zsh`.

The same scripts run on both platforms. Module checks adapt automatically: `launchctl`, `socketfilterfw`, `tmutil`, `mdfind` and `csrutil` on macOS; `systemctl`, `ufw`, and `firewalld` on Linux. Module **P** runs only on macOS and skips silently elsewhere. No native Windows support; WSL2 works as a Linux target.

## What it does

- **Fifteen audit modules (A–N plus P)** covering credentials, AI tool configuration, token scope, environment separation, backups, sandboxing, supply-chain compromise indicators (Nx-style and post-Nx), browser and password-manager session state, network egress, credential leakage in shell history and AI session transcripts (with per-secret service classification), AI hooks and repository-level configs, agent skills supply chain, MCP server inventory, known compromised packages, and macOS-specific privacy and persistence checks.
- **Five reports per run.** `audit-report.md` is human-readable and grouped by severity, with full remediation per finding. `audit-report.json` contains every finding for scripting and diffing across runs, plus a security score, grade letter, and per-service secrets summary. `audit-report.html` is a self-contained cyberpunk-themed HTML view that auto-opens in the browser at the end of the run — score gauge, severity strip, secrets table, collapsible findings, ASCII skull on sub-50 scores. `secrets-inventory.md` lists every detected credential pattern, classified by service, with a redacted fingerprint and a direct pointer to the right rotation panel. `action-plan.md` is the prioritised checklist — start here. It presents a summary-by-service rotation table plus per-source breakdown, then groups findings into TODAY (critical) / THIS WEEK (high) / THIS MONTH (medium) buckets so you can work top-to-bottom without re-reading the full report.

- **Security score (0-100).** Single-number summary: `100 − 5×CRITICAL − 1.7×HIGH − 0.3×MEDIUM − 0.05×LOW − (distinct_secrets ÷ 20, capped 10)`, floored at 0. Grades from S (≥90, "Hardened") through F (<30, "Pwned-Ready"). Score is displayed in `audit-report.json`, `audit-report.md`, and the HTML report. It is intentionally pessimistic — a developer machine should aim for 70+, hardened ones reach 90+. Anything below 50 is the "rotate everything" zone.
- **Hard guarantees.** Read-only on the host filesystem outside the output directory. No network calls. No secret values are ever written to disk or shown on screen — only paths, types, counts, and `XXXX****YYYY (N chars)` fingerprints sufficient to identify which key it is in your provider UI but insufficient to use.

## Requirements

**Required:** `bash`, and standard POSIX tools (`find`, `grep`, `stat`, `sed`).

**Optional** — modules degrade gracefully when these are missing:

| Tool | Used by | Behaviour without it |
|------|---------|----------------------|
| `jq` | aggregator (preferred field decoder), MCP module (M) for accurate parsing | Falls back to `python3` → `perl` → `sed`. Module M switches to a heuristic grep parser. |
| `python3` | aggregator fallback when `jq` is absent | Falls back to `perl` → `sed`. |
| `perl` | aggregator final fallback | Falls back to `sed` with reduced fidelity for escaped quotes. |
| `sqlite3` | J — Cursor / Atuin chat-history scan | Cursor and Atuin checks are skipped. |
| `gh` | A.7 / G.3 — GitHub token scope, s1ngularity-repo check | Those checks are skipped. |
| `npm` | A.3 / G / N — npm token check, Nx version detection, compromised-package scan | npm-based checks are skipped. |
| `pip3` / `pip` | N — compromised pip packages | pip checks are skipped. |
| `aws` | A.2 / C — AWS profile inspection | AWS-specific checks are degraded. |
| `op` / `bw` | H — 1Password / Bitwarden session state | Password-manager checks are skipped. |
| `ssh-keygen` / `ssh-add` | A.1 — passphrase test, ssh-agent state | The SSH passphrase check becomes less reliable. |
| `security`, `tmutil`, `mdfind`, `csrutil`, `spctl`, `xattr`, `PlistBuddy`, `brew` | P — macOS-specific | Module P degrades on macOS or skips entirely on Linux. |

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
bash scripts/run-audit.sh --modules A,B,J,M
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
| **J** | Sessions and history (with classification) | Per-secret classification of `bash` / `zsh` / `fish` / `atuin` / `psql` / `mysql` / `node` / `python` / `sqlite` history; Claude Code session JSONL files (`~/.claude/projects/*/sessions/`); Claude Code global prompt history (`~/.claude/history.jsonl`); Cursor SQLite chat history (`state.vscdb`) and per-workspace storage; Aider input and chat history; Cline state. Each detected match is classified by service and persisted with a redacted fingerprint to `secrets-inventory.md`. |
| **K** | AI hooks and repo-level configs | Globally-defined Claude Code hooks (`~/.claude/settings.json`); repository-level `.claude/`, `.cursor/`, `.windsurf/`, `.codeium/` configs in workspace; `CLAUDE.md` / `AGENTS.md` / `.cursorrules` scanned for zero-width and bidi-control characters, classic prompt-injection language ("ignore previous instructions"), and explicit safety-bypass instructions |
| **L** | AI skills supply chain | Inventory of skills and plugins under `~/.claude/skills`, `~/.claude/plugins`, per-project `.claude/skills/`, and Cursor extension dirs; flags recently installed entries (under thirty days), zero-width characters in `SKILL.md`, "skip approval / exfiltrate / silently" patterns, and `curl` or `wget` piped into a shell |
| **M** | MCP server inventory and risk | Walks every MCP configuration (Claude Desktop, Cursor, Windsurf, Codeium, Cline, per-project `.mcp.json`); for each declared server, classifies the launch method (`npx` unpinned, `npx` pinned, `uvx`, `docker`, local path) and flags supply-chain exposure; per-server plaintext-secret detection separate from module B |
| **N** | Compromised package detection | IOC database for known-bad releases: Nx 20.9.0–21.8.0, axios 1.14.1 / 0.30.4 (March 2026), `@bitwarden/cli` 2026.4.0, `prettier-vscode-plus` VS Code extension. Scans npm globally and via workspace `package.json`, scans pip, scans IDE extension directories. |
| **P** | macOS-specific | TCC.db audit (apps with Full Disk Access / AppleEvents / Accessibility / Screen Recording / Camera / Microphone), LaunchAgents and LaunchDaemons (persistence), keychain unlock policy, Time Machine destination encryption, third-party Homebrew taps, Spotlight indexing of `~/.aws` and `~/.ssh`, SIP and Gatekeeper status, quarantine flag on recent downloads, autonomous-agent app inventory (Codex, Claude, Cursor, Windsurf). Skips on Linux. |

## Secrets inventory

Module J classifies every detected credential pattern by **service**, **what to rotate**, and **severity hint**, and writes a per-source table to `secrets-inventory.md`. No raw values are written anywhere; only redacted fingerprints sufficient for identifying which key it is in your provider UI when rotating.

The fingerprint format is `XXXX****YYYY (N chars)` — for example `AKIA****ABCD (20 chars)`, `ghp_****wxyz (40 chars)`, or `sk-a****7890 (50 chars)`. Four leading characters preserve the vendor prefix that identifies the service. Four trailing characters and the length are usually enough to match the entry in a vendor's keys-list view. The middle bytes are never exposed.

Coverage is roughly forty specialised patterns:

- **Cloud.** AWS (`AKIA`, `ASIA` short-lived STS), Google (`AIza`, `ya29.`), DigitalOcean (`dop_v1_`).
- **AI providers.** Anthropic (`sk-ant-`, `sk-ant-api03-`), OpenAI (`sk-proj-`, `sk-svcacct-`, legacy `sk-`), HuggingFace (`hf_`), Replicate (`r8_`).
- **Stripe.** LIVE keys (`sk_live_`, `rk_live_`) flagged as `CRITICAL` severity hint; TEST keys flagged as `MEDIUM` or `LOW`.
- **Source-control hosts.** GitHub (`ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`), GitLab (`glpat-`).
- **Package registries.** npm (`npm_`), PyPI (`pypi-AgEIc`).
- **Communication.** Slack (`xoxb-`, `xoxp-`, `hooks.slack.com/services/...`), Discord webhooks, Telegram bot tokens.
- **Database connection strings.** Postgres, MySQL, MongoDB, Redis, AMQP — each detected only when an embedded password is present.
- **Generic high-value patterns.** Raw PEM private keys, JWTs (`eyJ...`).

Each row in the inventory tells you exactly where to go to rotate that specific key — for example *"OpenAI Project Key → platform.openai.com → API keys → Revoke"*, or *"AWS Access Key (long-lived IAM) → AWS Console → IAM → Users → Security credentials → Deactivate/Delete access key"*.

## Output

After a run:

```
~/.ai-agent-audit/
├── action-plan.md            # prioritised checklist — start here
├── audit-report.html         # cyberpunk-themed HTML — auto-opens in browser
├── audit-report.md           # human-readable, severity-grouped, full remediation per finding
├── audit-report.json         # all findings as JSON, with score + secrets summary
├── secrets-inventory.md      # per-source classified secrets, redacted fingerprints, rotate URLs
└── findings/
    ├── A.jsonl
    ├── B.jsonl
    └── ...
```

**Read order: the HTML report auto-opens — start there for the visual / score view, then `action-plan.md` for the actionable checklist.** The HTML contains everything (score, secrets table, findings) at a glance with a Matrix-style aesthetic. The action plan is plain markdown for those who prefer a terminal-only workflow. The other three artefacts are for machine consumption, deep-detail browsing, and per-source secret rotation.

## Severity rubric

- **CRITICAL** — directly enables a documented incident class. SSH key without passphrase plus loaded `ssh-agent`, compromised Nx or axios or Bitwarden CLI version, `shutdown` injection in shell init, compromised IDE extension installed.
- **HIGH** — significantly amplifies blast radius. Long-lived AWS keys, `.env` files in workspace, secrets in shell history, MCP servers launched via unpinned `npx`, repository-level configs containing executable hooks.
- **MEDIUM** — hygiene issue. Loose file permissions, single AWS profile, no backup tool, recently installed third-party skills, MCP servers using `npx` even when version-pinned.
- **LOW** — best-practice deviation.
- **INFO** — context, no action needed.

## Privacy and safety guarantees

- **Read-only.** The audit never writes outside `~/.ai-agent-audit/` (or `--output`).
- **No network.** Nothing is sent anywhere. The audit does not perform TruffleHog-style verification calls against vendor APIs to test whether a detected secret is still active. This is by design — the no-network policy is more important than reducing false positives. Treat every detected match as live and rotate accordingly.
- **No secret values.** Credential patterns are detected by regex, but findings record only path, type, count, and a redacted fingerprint. The user verifies any flagged credential manually with the suggested `grep` command.
- **No auto-remediation.** Findings include remediation steps, but every fix is run by the user. Especially for token rotation and file deletion — the audit will not act for you.

## Useful commands after a run

```bash
# Inspect raw findings:
cat ~/.ai-agent-audit/findings/A.jsonl | jq

# Count findings by severity:
jq -r .severity ~/.ai-agent-audit/findings/*.jsonl | sort | uniq -c

# All CRITICAL items:
grep -h CRITICAL ~/.ai-agent-audit/findings/*.jsonl | jq

# Read the classified secrets inventory before rotating:
less ~/.ai-agent-audit/secrets-inventory.md

# Re-run a single module or a cluster:
bash scripts/run-audit.sh --modules G
bash scripts/run-audit.sh --modules J,K,L,M  # the AI-specific cluster
```

## Project structure

```
ai-agent-audit/
├── README.md                          # this file
├── SKILL.md                           # Claude skill entry point
├── scripts/
│   ├── run-audit.sh                   # main orchestrator
│   ├── aggregate.sh                   # JSONL → JSON + Markdown
│   ├── purge-secrets.sh               # remove detected credential lines (dry-run by default)
│   ├── lib/
│   │   ├── common.sh                  # shared helpers, OS detection, json_decode_field
│   │   ├── secrets.sh                 # secret classification database, redact_fingerprint
│   │   ├── action_plan.sh             # generates action-plan.md from findings + inventory
│   │   └── html_report.sh             # generates cyberpunk-themed audit-report.html + score
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
│       ├── J_history_sessions.sh      # secret classification + fingerprint redaction
│       ├── K_hooks.sh                 # AI hooks + repo-level configs
│       ├── L_skills.sh                # agent skills supply chain
│       ├── M_mcp.sh                   # MCP inventory and risk
│       ├── N_packages.sh              # compromised package IOCs
│       └── P_macos.sh                 # macOS-specific
└── references/
    ├── incident-catalog.md            # documented incidents driving the checks
    └── remediation-guides.md          # vendor-specific fix steps
```

## Limitations

- Heuristic regex on history and session files produces false positives — example tokens inside documentation, redacted snippets, regex literals in code. Always verify before treating a finding as a real leak. The fingerprint helps: if the leading four characters match an obvious example like `AKIA0000` or `ghp_xxxx`, deprioritise.
- Local machine only. The audit does not inspect remote servers or CI runners.
- Module H is intentionally minimal. Reading browser SQLite cookie stores would expose live session tokens, which would violate the no-secret-values guarantee.
- Module N's IOC list is a static snapshot. New supply-chain attacks (after April 2026) require adding rows to the `NPM_COMPROMISED`, `PIP_COMPROMISED`, or `EXT_COMPROMISED` arrays.
- No verification step. Unlike TruffleHog, this audit does not ping vendor APIs to test whether a detected secret is still active — the no-network policy takes priority. Treat every match as live and rotate.
- Active prompt-injection attacks are not detected. The audit reports post-hoc indicators of compromise — zero-width characters in rules files, suspicious instruction language, persistent session artifacts — not zero-day session tampering.

## License

MIT
