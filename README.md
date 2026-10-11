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
# macOS (stock bash is 3.2): "$(brew --prefix)/bin/bash" ~/.claude/skills/ai-agent-audit/scripts/run-audit.sh
# HTML report auto-opens in your browser at the end.
```

**Or — let Claude Code handle it.** Drop one of these prompts into any session:

> Run the ai-agent-audit skill — full scan, then open the HTML report and summarise the top 3 critical findings plus what to rotate first.

> Audit my dev machine for AI agent risks. Use the ai-agent-audit skill, run all modules, then walk me through the action plan from highest priority down.

> Use the ai-agent-audit skill to scan this machine, focusing on Nx-style supply-chain indicators (module G) and the secrets inventory. Tell me which keys to rotate today.

Claude reads `SKILL.md`, runs `bash scripts/run-audit.sh`, parses the reports (`audit-report.md`, `audit-report.json`, `secrets-inventory.md`, `action-plan.md`; the fifth, `audit-report.html`, is for you), and summarises with severity-ordered recommendations. The HTML report opens automatically in your default browser unless you pass `--no-open`.

**One-line score check** (after a run):

```bash
jq -r '"\(.score)/100 [\(.grade) — \(.grade_label)]   crit:\(.summary.critical) high:\(.summary.high) secrets:\(.summary.secrets_distinct)"' ~/.ai-agent-audit/audit-report.json
```

**Purge detected secrets from history / sessions** (separate utility, dry-run by default):

```bash
# Dry-run — shows what would be removed, makes no changes
bash scripts/purge-secrets.sh

# Redact in place (originals backed up to ~/.ai-agent-audit/purge-backups/<timestamp>/)
bash scripts/purge-secrets.sh --purge

# Also wipe Cursor SQLite chat storage (opt-in)
bash scripts/purge-secrets.sh --purge --include-cursor
```

The purge script replaces each detected credential with `[REDACTED:<fingerprint>]` in shell histories, `~/.claude/history.jsonl`, every Claude Code session (`~/.claude/projects/*/*.jsonl`), Claude Code file-history snapshots (`~/.claude/file-history/`), Codex history and sessions, and Cline task state. Line count and JSONL structure stay intact, so sessions remain resumable; `--delete-lines` restores the old delete-the-whole-line behaviour. It uses the HIGH/CRITICAL patterns from `lib/secrets.sh` and skips local docker / loopback database URLs (`postgres://user:pass@localhost/...` is not a real leak). Raw PEM private keys are reported by the audit but not purged. Originals are copied to `~/.ai-agent-audit/purge-backups/<timestamp>/` (mode 600) — they contain the secrets, so delete them once you have checked the result, or pass `--no-backup`. Close running agent sessions first, and rotate in your provider UIs **before** purging: redaction removes the trail, it does not un-leak the key.

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

Runs on **Linux** (Debian/Ubuntu, Fedora, Arch) and **macOS** (Intel and Apple Silicon); CI runs the test suite on Ubuntu and macOS. The scripts need **bash 4.4 or newer**. Stock macOS ships bash 3.2 as `/bin/bash`, so install a current one (`brew install bash`) and run the audit with it: `"$(brew --prefix)/bin/bash" scripts/run-audit.sh`. The audit exits with that hint if it is started under an older bash. Your login shell can stay `zsh`.

The same scripts run on both platforms. Module checks adapt automatically: `socketfilterfw`, `tmutil`, `diskutil`, `mdutil`, `csrutil` and the TCC database on macOS; `systemctl`, `ufw`, and `firewalld` on Linux. Module **P** runs only on macOS and skips silently elsewhere. No native Windows support; WSL2 works as a Linux target.

## What it does

- **Fifteen audit modules (A–N plus P)** covering credentials, AI tool configuration, token scope, environment separation, backups, sandboxing, supply-chain compromise indicators (Nx-style and post-Nx), browser and password-manager session state, network egress, credential leakage in shell history and AI session transcripts (with per-secret service classification), AI hooks and repository-level configs, agent skills supply chain, MCP server inventory, known compromised packages, and macOS-specific privacy and persistence checks.
- **Five reports per run.** `audit-report.md` is human-readable and grouped by severity, with full remediation per finding. `audit-report.json` contains every finding for scripting and diffing across runs, plus a security score, grade letter, and per-service secrets summary. `audit-report.html` is a self-contained cyberpunk-themed HTML view that auto-opens in the browser at the end of the run — score gauge, severity strip, secrets table, collapsible findings, a ☠ status badge below 30. `secrets-inventory.md` lists every detected credential pattern, classified by service, with a redacted fingerprint and a direct pointer to the right rotation panel. `action-plan.md` is the prioritised checklist — start here. It presents a summary-by-service rotation table plus per-source breakdown, then groups findings into TODAY (critical) / THIS WEEK (high) / THIS MONTH (medium) buckets so you can work top-to-bottom without re-reading the full report.

- **Security score (0-100).** Single-number summary. Score = 100 − 5×CRITICAL − 2.5×HIGH − 0.3×MEDIUM − 0.05×LOW − (distinct secrets ÷ 15, capped at 15) − 10 if compound supply-chain risk (MCP server via unpinned npx + npm or GitHub publish-capable credentials), floored at 0. A key found in several files counts once. Grades from S (≥90, "Hardened") through F (<30, "Pwned-Ready"). Score is displayed in `audit-report.json`, `audit-report.md`, and the HTML report. It is intentionally pessimistic — a developer machine should aim for 70+, hardened ones reach 90+. Anything below 50 is the "rotate everything" zone.
- **Hard guarantees.** Read-only on the host filesystem outside the output directory (`purge-secrets.sh` is the separate, opt-in exception). No network calls. No secret values are ever written to disk or shown on screen — only paths, types, counts, and `XXXX****YYYY (N chars)` fingerprints sufficient to identify which key it is in your provider UI but insufficient to use.

## Requirements

**Required:** `bash` 4.4 or newer (macOS: `brew install bash`), and standard POSIX tools (`find`, `grep`, `stat`, `sed`, `awk`).

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

### Which project directories are scanned

Repo-level checks (`.env` files, `CLAUDE.md` / `.cursorrules`, `.claude/settings.json`, `.mcp.json`, `package.json`, git remotes) walk a set of project roots. By default they come from where your agents actually ran: the `projects` keys in `~/.claude.json` and the `[projects."<path>"]` entries in `~/.codex/config.toml`, plus the conventional `~/projects`, `~/code`, `~/dev`, `~/work`, `~/repos`, `~/src`. A parent holding more than three known projects is scanned as one root, `$HOME` itself is never a root, and at most 60 roots are kept. The report lists the roots it used in the `X.roots` finding. To choose them yourself:

```bash
AUDIT_DEV_PATHS="$HOME/work:$HOME/clients" bash scripts/run-audit.sh
```

## Modules

| ID | Domain | Key checks |
|----|--------|------------|
| **A** | Credentials | SSH keys (passphrase, perms, ssh-agent loaded), AWS / GCP / Azure / Kubernetes contexts, npm / cargo / pypi / docker tokens, GitHub and GitLab CLI tokens, `git-credentials`, `~/.netrc`, `~/.pgpass`, Terraform Cloud and Vault tokens, `.env` files in project roots, GPG, crypto wallets |
| **B** | AI tool config | Installed AI CLIs, permission-bypass aliases and env vars in shell init (`--yolo`, `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--full-auto`, ...), MCP config permissions and `npx` use, Claude Code settings (`permissions.defaultMode: bypassPermissions`, `Bash` allow-all, `enableAllProjectMcpServers`, custom `ANTHROPIC_BASE_URL`) |
| **C** | Token scope | GitHub token type (classic PAT vs fine-grained), AWS SSO vs long-lived keys, npm token count |
| **D** | Environment separation | Distinct AWS profiles, SSH host aliases, production `DATABASE_URL` in a dev project, `.env` covered by `.gitignore` |
| **E** | Backup hygiene | Backup tool presence (`restic`, `borg`, an active Time Machine), git remote diversity (read from `.git/config`) |
| **F** | Sandbox / isolation | Container / devcontainer / WSL detection, group memberships (`docker`, `sudo`, `wheel`), passwordless sudo (`NOPASSWD: ALL`), sudo cache state |
| **G** | Supply-chain compromise indicators | `shutdown` injection in shell init, `s1ngularity-repository*` and Shai-Hulud repos on your GitHub account, Shai-Hulud payload files in `node_modules`, `/tmp/inventory.txt`, suspicious npm install scripts. Compromised Nx versions are covered by module N. |
| **H** | Browser / password manager | Browser data presence, 1Password / Bitwarden unlock state |
| **I** | Network egress | Firewall (`ufw` per `ufw.conf`, `firewalld`, `nftables`, `socketfilterfw`), outbound firewall (Little Snitch / LuLu on macOS), `HTTP_PROXY` |
| **J** | Sessions and history (with classification) | Per-secret classification of `bash` / `zsh` / `fish` / `atuin` / `psql` / `mysql` / `node` / `python` / `sqlite` history; Claude Code sessions (`~/.claude/projects/*/*.jsonl`, newest 500 of the last 90 days), global prompt history, file-history and shell snapshots; Codex history and sessions; Gemini CLI chats; Cursor SQLite chat history; Aider history; Cline task transcripts. Each match is classified by service and stored only as a redacted fingerprint in `secrets-inventory.md`. |
| **K** | AI hooks and repo-level configs | Global hooks (Claude Code, Gemini CLI, managed settings) and installed plugin hooks; repository-level `.claude/`, `.cursor/`, `.windsurf/`, `.codeium/` configs with hooks, permission allow-lists, env overrides or `apiKeyHelper`; `CLAUDE.md` / `GEMINI.md` / `AGENTS.md` / `.cursorrules` / Copilot instructions / `.claude/agents` and `.claude/commands` scanned for zero-width and bidi-control characters, prompt-injection language, safety-bypass instructions and instructions hidden in HTML comments |
| **L** | AI skills supply chain | Every `SKILL.md` under `~/.claude/skills`, `~/.claude/plugins`, Cursor skill dirs and per-project `.claude/skills/`; flags recently installed skills (under thirty days), zero-width characters, "skip approval / exfiltrate / without telling the user" instructions, and downloads piped into a shell |
| **M** | MCP server inventory and risk | Every MCP configuration (Claude Code user and project scope in `~/.claude.json`, Claude Desktop, Cursor, Windsurf, Gemini CLI, Codex `config.toml`, Cline, per-project `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json`); classifies each server's launch method (`npx` unpinned or pinned, `uvx`, `docker`, local path, remote `http`/`sse`) and flags supply-chain and plaintext-transport exposure |
| **N** | Compromised package detection | One IOC list for known-bad releases: Nx 20.9.0–20.12.0 and 21.5.0–21.8.0, axios 1.14.1 / 0.30.4 (March 2026), `@bitwarden/cli` 2026.4.0, `prettier-vscode-plus` VS Code extension. Checks global npm installs, declared versions in `package.json`, resolved versions in `node_modules` and `package-lock.json`, pip, and IDE extension directories. |
| **P** | macOS-specific | TCC.db audit (apps with Full Disk Access / AppleEvents / Accessibility / Screen Recording / Camera / Microphone; INFO when the database is unreadable), LaunchAgents and LaunchDaemons (persistence, `com.apple.*` masquerading in the user's LaunchAgents), keychain unlock policy, Time Machine destination encryption (via `diskutil`), third-party Homebrew taps, Spotlight indexing, SIP and Gatekeeper status, quarantine flag on recent downloads and `.app` bundles, autonomous-agent app inventory (Codex, Claude, Cursor, Windsurf). Skips on Linux. |
| **X** | Run context | Which project roots the repo-level checks scanned (see above). |

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
- **Redaction safety net.** Every finding's title, evidence and remediation passes through the secret-pattern redactor before it is written, so a command line or config value that happens to embed a token is stored as `[REDACTED]`. Text copied from files an attacker could control (repo rules files, hook commands, launch agents) is redacted, stripped of control characters, cut to 80 characters and prefixed with `[untrusted content]`, because AI agents read these reports.
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
├── CHANGELOG.md
├── .github/workflows/ci.yml           # shellcheck + tests on Ubuntu and macOS
├── docs/
│   ├── usage-guide.md                 # interpreting results, agent verification prompt
│   └── improvement-plan-2026-10.md    # the October 2026 hardening plan
├── tests/
│   ├── run.sh                         # runs every tests/test_*.sh against a fake HOME
│   └── lib.sh                         # fixtures, stubs, assertions
├── scripts/
│   ├── run-audit.sh                   # main orchestrator
│   ├── aggregate.sh                   # JSONL → JSON + Markdown
│   ├── purge-secrets.sh               # redact detected credentials in place (dry-run by default)
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
│       └── P_macos.sh                 # macOS-specific (X.roots is written by run-audit.sh)
└── references/
    ├── incident-catalog.md            # documented incidents driving the checks
    └── remediation-guides.md          # vendor-specific fix steps
```

## Development

Tests run against a throwaway `HOME` with stubbed `gh`, `npm`, `sudo` and friends, so they never read your real credentials or hit the network:

```bash
bash tests/run.sh
shellcheck -S warning scripts/*.sh scripts/lib/*.sh scripts/modules/*.sh tests/*.sh
```

Every behaviour change ships with a test in `tests/test_*.sh` (helpers in `tests/lib.sh`). Fixture secrets are generated at test time with `fake_secret`, never committed. CI runs both commands on Ubuntu and macOS (Homebrew bash).

## Limitations

- Heuristic regex on history and session files produces false positives — example tokens inside documentation, redacted snippets, regex literals in code. Always verify before treating a finding as a real leak. The fingerprint helps: if the leading four characters match an obvious example like `AKIA0000` or `ghp_xxxx`, deprioritise.
- Local machine only. The audit does not inspect remote servers or CI runners.
- Module H is intentionally minimal. Reading browser SQLite cookie stores would expose live session tokens, which would violate the no-secret-values guarantee.
- Module N's IOC list is a static snapshot. New supply-chain attacks (after April 2026) require adding rows to the `NPM_COMPROMISED`, `PIP_COMPROMISED`, or `EXT_COMPROMISED` arrays.
- No verification step. Unlike TruffleHog, this audit does not ping vendor APIs to test whether a detected secret is still active — the no-network policy takes priority. Treat every match as live and rotate.
- Active prompt-injection attacks are not detected. The audit reports post-hoc indicators of compromise — zero-width characters in rules files, suspicious instruction language, persistent session artifacts — not zero-day session tampering.

## License

MIT
