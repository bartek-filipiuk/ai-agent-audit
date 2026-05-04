# ai-agent-audit — usage guide

How the tool works, how to interpret results, and how to feed findings to an AI agent for verification.

## Quick start

```bash
git clone https://github.com/bartek-filipiuk/ai-agent-audit.git ~/.claude/skills/ai-agent-audit
chmod +x ~/.claude/skills/ai-agent-audit/scripts/*.sh \
         ~/.claude/skills/ai-agent-audit/scripts/lib/*.sh \
         ~/.claude/skills/ai-agent-audit/scripts/modules/*.sh
bash ~/.claude/skills/ai-agent-audit/scripts/run-audit.sh
```

HTML report opens in your default browser. All output lives in `~/.ai-agent-audit/`.

## What gets scanned

| Module | Domain | Notes |
|---|---|---|
| A | Credentials | SSH, AWS/GCP/Azure/K8s, npm/cargo/pypi/docker tokens, GitHub CLI, .env files, GPG, crypto wallets |
| B | AI tool config | Installed CLIs, dangerous flags in shell init, MCP configs, project rules |
| C | Token scope | GitHub PAT type, AWS long-lived vs SSO, npm token count |
| D | Environment separation | dev/prod profile counts, SSH host aliases, .gitignore for .env |
| E | Backup hygiene | restic/borg/TimeMachine presence |
| F | Sandbox / isolation | container detection, group memberships, sudo cache |
| G | Nx-style compromise | known compromised Nx versions, shutdown injection, /tmp/inventory.txt |
| H | Browser / password manager | browser data presence, 1P/Bitwarden unlock state |
| I | Network egress | firewall, outbound firewall, HTTP_PROXY |
| J | Sessions + history | per-secret classification across shell histories, Claude/Cursor sessions, Cline state |
| K | AI hooks + repo configs | global hooks, repo-level configs, prompt-injection patterns in CLAUDE.md/AGENTS.md |
| L | AI skills supply chain | recently-installed skills, suspicious SKILL.md patterns |
| M | MCP server inventory | per-server launch method classification, npx pinned vs unpinned |
| N | Compromised packages | IOC list (Nx 20.9.0–21.8.0, axios 1.14.1/0.30.4, @bitwarden/cli 2026.4.0, prettier-vscode-plus) |
| P | macOS-specific | TCC.db, LaunchAgents, Time Machine, Spotlight, SIP — Linux skip |

## Output artefacts

```
~/.ai-agent-audit/
├── action-plan.md            # prioritised checklist — start here
├── audit-report.html         # cyberpunk dashboard (auto-opens)
├── audit-report.md           # full markdown report
├── audit-report.json         # machine-readable + score + secrets summary
├── secrets-inventory.md      # per-source classified secrets, redacted fingerprints
└── findings/
    ├── A.jsonl
    ├── B.jsonl
    └── ...
```

## Interpreting the score

Formula:
```
score = 100
       − 5    × CRITICAL
       − 2.5  × HIGH
       − 0.3  × MEDIUM
       − 0.05 × LOW
       − min(distinct_secrets / 15, 15)
       − 10 if (MCP_unpinned ≥ 1) AND (npm publish token OR GitHub PAT with workflow scope)
floor 0
```

Grade table:

| Score | Grade | Label |
|---|---|---|
| 90-100 | S | Hardened |
| 80-89 | A | Solid |
| 70-79 | B | OK-ish |
| 60-69 | C | Concerning |
| 50-59 | D | At Risk |
| 30-49 | E | Critical Exposure |
| 0-29 | F | Pwned-Ready (skull rendered) |

The compound penalty captures the "I am a supply-chain distributor" meta-risk: if you have unpinned MCP (= you run untrusted code at every agent invocation) AND publish-capable npm/gh tokens (= you ship code others install), a single trojaned upstream cascades beyond your host.

A typical developer host starts at 30-50. A hardened one reaches 90+. Anything under 50 is the "rotate everything" zone.

## Severity rubric — what each level actually means

- **CRITICAL** — directly enables a documented incident class. SSH key without passphrase plus loaded ssh-agent, compromised Nx/axios/Bitwarden CLI version, shutdown injection in shell init, compromised IDE extension installed, claude-dev-style permission-bypass alias.
- **HIGH** — significantly amplifies blast radius if anything goes wrong. Long-lived AWS keys, .env files in workspace, secrets in shell history, MCP servers launched via unpinned npx, repo-level configs containing executable hooks, GitHub PAT with destructive scopes.
- **MEDIUM** — hygiene issue. Loose file permissions, single AWS profile, no backup tool, recently installed third-party skills, MCP servers using pinned npx (better than unpinned, still supply-chain risk).
- **LOW** — best-practice deviation.
- **INFO** — context, no action needed.

## False positives — what to expect

The audit is intentionally pessimistic. Common false positives:

- **Documentation placeholders** — `AKIAIOSFODNN7EXAMPLE`, `ghp_xxxxxxxxwxyz`, `sk_live_xxxxxxxxaaaa` from tutorials and READMEs. The fingerprint format helps: clearly suspicious-looking patterns (lots of `x`, ending in obvious filler like `wxyz`) are usually placeholders.
- **Local docker DB URLs** — `postgres://user:pass@localhost/db`, `@db`, `@postgres-container`. The audit excludes these by default (compares hostname against local-network whitelist).
- **JWT fragments from dev/test** — `eyJ...` strings from session tokens in dev environments. Often valid technically but no production blast radius.
- **Recently-installed skill subdirectories** — module L flags `~/.claude/skills/<name>/references/` as separate skills. Known limitation.
- **HTTP-type MCP servers** — module M flags HTTP MCP (`"type": "http"`) as "unknown launcher". HTTP transport is legit; the audit just doesn't categorize it.

## Feeding findings to an AI agent for verification

The audit reports raw findings. To verify whether each is a real vulnerability or false positive in your specific context, pipe selected findings into an AI agent with this prompt template:

```
You are reviewing a security audit finding from ai-agent-audit. Your job: classify
this finding as REAL_VULNERABILITY, FALSE_POSITIVE, or REQUIRES_INSPECTION.

For each finding I give you:
1. Read the title, evidence, and remediation fields.
2. Classify per the rules below.
3. If REAL_VULNERABILITY: state the concrete attack scenario in one sentence.
4. If FALSE_POSITIVE: state why (matches a known exclusion pattern below).
5. If REQUIRES_INSPECTION: state the one command I should run to disambiguate.

Rules for FALSE_POSITIVE:
- Secret fingerprint matches a documentation placeholder pattern (ends in 'EXAMPLE',
  'wxyz', 'aaaa', '7890', or starts with `sk_live_xxxx`-style filler).
- Postgres/MySQL/Redis URL points at @localhost / @127.x / @0.0.0.0 / @host.docker.internal /
  @<docker-container-name> — local-only network exposure.
- JWT pattern (eyJ...) found in plain text — likely a regex fragment from documentation
  or a dev/test session token, not a production secret.
- "Recently installed skill" finding in module L where the path contains
  `/references/` — that's a subdirectory, not a separate skill.
- MCP server with "type": "http" reported as M.2.unknown — HTTP transport is legit.
- npm token in ~/.npmrc that returns 401 from `npm whoami` — already revoked,
  the file just hasn't been cleaned up.

Rules for REAL_VULNERABILITY:
- SSH private key without passphrase (A.1.nopass).
- Shell alias bypassing AI agent permission prompts (B.2.alias).
- Compromised package version detected (any N.* finding).
- Plaintext bearer/api_key/password in MCP config or .npmrc that authenticates
  successfully against the target service.
- Repo-level hook (.claude/settings.json hooks, .cursor/settings.json) in a
  cloned repo whose remote.origin.url is from a third party.
- ssh-agent loaded with multiple keys AND no per-shell override — keys are
  available to every child process including AI agents.

Rules for REQUIRES_INSPECTION:
- Generic high-entropy string match (Unknown high-entropy string in module J) —
  needs human eyeball on the surrounding context.
- Repo-level CLAUDE.md / AGENTS.md found — requires reading the file content
  to check for prompt-injection patterns the static scan didn't flag.
- Discord webhook URL found — write-only target, low-risk but worth confirming
  it's a webhook you actually own.

Output format (one block per finding):
- ID: [module.id]
- Classification: REAL_VULNERABILITY | FALSE_POSITIVE | REQUIRES_INSPECTION
- Reason: <one sentence>
- Action: <imperative one-liner: rotate, ignore, or investigate>

Findings:
<paste JSON or markdown findings here>
```

Use this as the system prompt when handing off the report to a code-review agent. Pair with the JSON output (`audit-report.json`) for machine-friendly piping:

```bash
jq '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL")' \
  ~/.ai-agent-audit/audit-report.json | <pipe to agent>
```

## Privacy and safety guarantees

- **Read-only.** Never writes outside `~/.ai-agent-audit/` (or `--output`).
- **No network.** No verification calls against vendor APIs. Treat every detected match as live and rotate.
- **No secret values on disk.** Detected credentials are stored as redacted fingerprints (`XXXX****YYYY (N chars)`) only.
- **No auto-remediation.** All findings include a remediation field; you run the fixes.

## Related utilities

- `scripts/purge-secrets.sh` — remove detected credential lines from history files and AI session storage. Dry-run by default. Pass `--purge` to actually delete (creates `.bak.<TIMESTAMP>` backups). Pass `--include-cursor` to also wipe Cursor SQLite. Note: rotate the secrets in your provider UIs **before** purge — deletion of a leaked-key entry doesn't un-leak the key, only removes the trail.

## Common patterns to watch

**SSH passphrase + gnome-keyring trap.** Adding a passphrase to an SSH key with `ssh-keygen -p` protects the file on disk, but if gnome-keyring captures the passphrase on first use it auto-unlocks the key for every process running as you. The fix is either: disable gnome-keyring's SSH module entirely (`mkdir -p ~/.config/autostart && cp /etc/xdg/autostart/gnome-keyring-ssh.desktop ~/.config/autostart/ && echo 'Hidden=true' >> ~/.config/autostart/gnome-keyring-ssh.desktop`), or use a per-shell ssh-agent override that ignores the keyring socket.

**MCP server `npx` pinning.** Even pinned (`@1.2.3`), `npx` re-resolves the registry at every invocation. For maximum safety: `npm i -g <pkg>@<version>` once, then point the MCP config at the absolute binary path (e.g. `/usr/local/bin/<server-cli>`). The audit reports pinned npx as MEDIUM and unpinned as HIGH.

**GitHub PAT scope creep.** `gh auth login` defaults to broad scopes for convenience. Refresh to minimum: `gh auth refresh --remove-scopes 'admin:org,delete_repo,workflow,write:packages,...' -s read:org`. For destructive ops (delete repo, run workflow), refresh ad hoc with the needed scope and back to minimum after.

## Limitations

- Heuristic regex on history and session files produces false positives. Fingerprint format helps; verify before treating any specific finding as a real leak.
- Local machine only. The audit does not inspect remote servers, CI runners, or cloud accounts.
- Module H is intentionally minimal — reading browser SQLite cookie stores would expose live session tokens, violating the no-secret-values guarantee.
- Module N's IOC list is a static snapshot. New supply-chain attacks require adding rows to `NPM_COMPROMISED` / `EXT_COMPROMISED` in `scripts/modules/N_packages.sh`.
- No verification step (vs TruffleHog). The no-network policy takes priority. Treat every match as live.
- Active prompt-injection attacks are not detected — only post-hoc indicators (zero-width chars in rules, suspicious instruction language, persistent session artifacts).
