#!/usr/bin/env bash
# Module B: AI tools configuration audit
# Detects installed AI CLI tools, dangerous flags, MCP server configs, plaintext secrets in MCP json.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="B"
log "$MODULE" "Starting AI tools config audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# ---------- B.1: Installed AI CLI tools ----------
declare -a AI_TOOLS=(claude gemini cursor cline aider codex q opencode)
installed_tools=()
for t in "${AI_TOOLS[@]}"; do
  if has "$t"; then
    installed_tools+=("$t")
  fi
done

if [[ ${#installed_tools[@]} -gt 0 ]]; then
  emit_finding "$MODULE" "INFO" "B.1.installed" \
    "AI CLI tools installed: ${installed_tools[*]}" \
    "Each tool has different permission model. Check individual configs below." "" ""
fi

# Cursor app (GUI)
if [[ -d "/Applications/Cursor.app" ]] || [[ -d "$HOME/.cursor" ]] || [[ -d "$HOME/.config/Cursor" ]]; then
  installed_tools+=("Cursor IDE")
  emit_finding "$MODULE" "INFO" "B.1.cursor.app" "Cursor IDE installed" "" "" ""
fi

# ---------- B.2: Dangerous flags in shell init ----------
SHELL_RC_FILES=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshenv" "$HOME/.config/fish/config.fish")
for rc in "${SHELL_RC_FILES[@]}"; do
  [[ -f "$rc" ]] || continue
  # Look for aliases or exports that bypass agent permissions
  if grep -nE 'alias\s+(claude|gemini|cursor|cline|aider).*-{1,2}(yolo|dangerously-skip-permissions|trust-all-tools|skip-permissions|no-interactive)' "$rc" 2>/dev/null; then
    line=$(grep -nE 'alias\s+(claude|gemini|cursor|cline|aider).*-{1,2}(yolo|dangerously-skip-permissions|trust-all-tools|skip-permissions|no-interactive)' "$rc" | head -1)
    emit_finding "$MODULE" "CRITICAL" "B.2.alias" \
      "Shell alias bypasses AI agent permission prompts in $rc" \
      "Line: $line" \
      "Remove the bypass flag from the alias. Use --yolo only inside an isolated container, never globally." \
      "Nx s1ngularity (Aug 2025) — exploited exactly these flags: --dangerously-skip-permissions, --yolo, --trust-all-tools"
  fi

  # Direct calls with bypass flags being set as defaults
  if grep -qE '(CLAUDE_|GEMINI_|CURSOR_).*=.*(yolo|skip-permissions|trust-all)' "$rc" 2>/dev/null; then
    line=$(grep -nE '(CLAUDE_|GEMINI_|CURSOR_).*=.*(yolo|skip-permissions|trust-all)' "$rc" | head -1)
    emit_finding "$MODULE" "CRITICAL" "B.2.env" \
      "Environment variable enables AI permission bypass in $rc" \
      "Line: $line" \
      "Unset the env var. These flags should be opt-in per-invocation, never global." \
      "Nx s1ngularity"
  fi
done

# ---------- B.3: MCP server configurations ----------
MCP_CONFIGS=(
  "$HOME/.cursor/mcp.json"
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
  "$HOME/.config/Claude/claude_desktop_config.json"
  "$HOME/.config/claude/mcp.json"
  "$HOME/.codeium/windsurf/mcp_config.json"
)

for cfg in "${MCP_CONFIGS[@]}"; do
  [[ -f "$cfg" ]] || continue
  emit_finding "$MODULE" "INFO" "B.3.found" "MCP config found: $cfg" "" "" ""

  # Check perms
  perms=$(file_perm_octal "$cfg")
  if [[ -n "$perms" && "$perms" != "600" && "$perms" != "400" ]]; then
    emit_finding "$MODULE" "MEDIUM" "B.3.perm" \
      "MCP config has loose permissions: $cfg ($perms)" \
      "" "chmod 600 \"$cfg\"" ""
  fi

  # Detect plaintext secrets (heuristic — common patterns)
  if grep -qE '"(api[_-]?key|token|password|secret|auth)"\s*:\s*"[A-Za-z0-9_\-\.]{16,}"' "$cfg" 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "B.3.secrets" \
      "MCP config contains plaintext secrets: $cfg" \
      "Detected key/token/password patterns. Trend Micro found 48% of MCP servers recommend this anti-pattern." \
      "Migrate to env-var injection at runtime, or use a secrets manager (Infisical, 1Password CLI). Rotate any exposed credentials." \
      "Trend Micro 2025 study — 24,000+ secrets leaked via MCP configs on public GitHub"
  fi

  # Detect npx-installed servers (run-on-install risk)
  if grep -qE '"command"\s*:\s*"npx"' "$cfg" 2>/dev/null; then
    emit_finding "$MODULE" "MEDIUM" "B.3.npx" \
      "MCP config uses 'npx' to launch servers: $cfg" \
      "npx fetches and executes the package on first run — supply chain risk if package is compromised." \
      "Pin specific versions, or install MCP servers globally with audited versions: npm i -g <pkg>@<version>." \
      "Nx s1ngularity demonstrated postinstall script abuse"
  fi
done

# ---------- B.4: Project rules files ----------
# CLAUDE.md, .cursorrules, .clinerules, AGENTS.md — anywhere in workspace
RULE_PATHS=()
for p in "$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work" "$HOME/repos" "$HOME/src"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r f; do
    [[ -n "$f" ]] && RULE_PATHS+=("$f")
  done < <(find "$p" -maxdepth 4 -type f \( -name 'CLAUDE.md' -o -name '.cursorrules' -o -name '.clinerules' -o -name 'AGENTS.md' \) -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
done

if [[ ${#RULE_PATHS[@]} -gt 0 ]]; then
  emit_finding "$MODULE" "INFO" "B.4.rules" \
    "${#RULE_PATHS[@]} agent rules file(s) in workspace" \
    "These files inject instructions into agent context. Atakers can use them as injection vector." "" ""

  # Check each for dangerous patterns
  for f in "${RULE_PATHS[@]}"; do
    # Look for instructions that might disable safety
    if grep -qiE '(skip|bypass|ignore|disable).*(confirmation|approval|safety|permission|prompt)' "$f" 2>/dev/null; then
      emit_finding "$MODULE" "HIGH" "B.4.danger" \
        "Rules file weakens agent safety: $f" \
        "Contains instructions that may disable safety prompts." \
        "Review and remove instructions that bypass confirmations. Agent should always require approval for destructive ops." \
        "Replit / Gemini / PocketOS — every documented incident violated 'don't do destructive ops without approval' rule"
    fi
  done
fi

# ---------- B.5: Cursor settings.json — auto-approve ----------
CURSOR_SETTINGS=("$HOME/Library/Application Support/Cursor/User/settings.json" "$HOME/.config/Cursor/User/settings.json")
for s in "${CURSOR_SETTINGS[@]}"; do
  [[ -f "$s" ]] || continue
  if grep -qE '"cursor\.(allowPrompt|autoApprove|alwaysAllow)"\s*:\s*true' "$s" 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "B.5.autoapprove" \
      "Cursor auto-approve enabled: $s" \
      "Tool calls execute without human review." \
      "Disable in settings.json: set cursor.autoApprove and similar to false. Use Plan Mode for review." \
      "Cursor's own December 2025 disclosure of Plan Mode enforcement bug"
  fi
done

# ---------- B.6: Claude Code settings ----------
CC_SETTINGS=("$HOME/.claude/settings.json" "$HOME/.config/claude-code/settings.json")
for s in "${CC_SETTINGS[@]}"; do
  [[ -f "$s" ]] || continue
  emit_finding "$MODULE" "INFO" "B.6.cc" "Claude Code settings: $s" "" "" ""
  # check for permissive allow list
  if grep -qE '"alwaysAllow"|"allowedTools".*Bash' "$s" 2>/dev/null; then
    emit_finding "$MODULE" "MEDIUM" "B.6.allow" \
      "Claude Code has broad alwaysAllow / allowedTools list: $s" \
      "Bash on always-allow significantly raises blast radius from prompt injection." \
      "Review settings. For Bash: prefer per-session allow rather than persistent." \
      "Clinejection (2025/2026) — agents configured with Bash always-allowed were RCE-able via issue title injection"
  fi
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
