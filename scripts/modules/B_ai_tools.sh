#!/usr/bin/env bash
# Module B: AI tools configuration audit
# Detects installed AI CLI tools, permission-bypass aliases and env vars, MCP config hygiene,
# and risky Claude Code settings.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="B"
log "$MODULE" "Starting AI tools config audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

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
  emit_finding "$MODULE" "INFO" "B.1.cursor.app" "Cursor IDE installed" "" "" ""
fi

# ---------- B.2: Dangerous flags in shell init ----------
SHELL_RC_FILES=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshenv" "$HOME/.config/fish/config.fish")
# An alias for any agent CLI that bakes in a permission-bypass flag.
BYPASS_ALIAS_RE="alias[[:space:]]+(claude|gemini|cursor|cline|aider|codex|opencode|copilot|goose|q)[=[:space:]].*(-{1,2}(yolo|dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox|full-auto|trust-all-tools|skip-permissions|no-interactive)|[[:space:]]-y([[:space:]]|['\"]|\$))"
for rc in "${SHELL_RC_FILES[@]}"; do
  [[ -f "$rc" ]] || continue
  # Look for aliases or exports that bypass agent permissions
  line=$(grep -nE "$BYPASS_ALIAS_RE" "$rc" 2>/dev/null | head -1)
  if [[ -n "$line" ]]; then
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

# MCP configurations (permissions, launchers, plaintext secrets) are audited by module M.

# Rules files (CLAUDE.md, .cursorrules, AGENTS.md, ...) are checked by module K (K.2, K.3).
# Cursor auto-run state lives in its SQLite state DB, not settings.json; the old
# settings.json keys this module grepped for do not exist.

# ---------- B.6: Claude Code settings ----------
CC_SETTINGS=("$HOME/.claude/settings.json" "$HOME/.claude/settings.local.json" "/etc/claude-code/managed-settings.json")
for s in "${CC_SETTINGS[@]}"; do
  [[ -f "$s" ]] || continue
  emit_finding "$MODULE" "INFO" "B.6.cc" "Claude Code settings: $s" "" "" ""
  flags=" $(claude_settings_flags "$s") "
  if [[ "$flags" == *" bypass "* ]]; then
    emit_finding "$MODULE" "HIGH" "B.6.bypass" \
      "Claude Code runs with permissions.defaultMode = bypassPermissions: $s" \
      "Every tool call, including Bash and file writes, runs without asking. A prompt injection in any file the agent reads executes immediately." \
      "Remove defaultMode or set it to \"default\". Use bypass only inside a disposable container." \
      "Nx s1ngularity (Aug 2025) — relied on exactly this kind of permission bypass"
  fi
  if [[ "$flags" == *" bashall "* || "$flags" == *" legacy "* ]]; then
    emit_finding "$MODULE" "MEDIUM" "B.6.allow" \
      "Claude Code allows every Bash command without asking: $s" \
      "permissions.allow contains Bash / Bash(*) (or the legacy alwaysAllow / allowedTools keys). Bash on always-allow significantly raises blast radius from prompt injection." \
      "Replace the blanket rule with specific commands, e.g. \"Bash(npm test:*)\", \"Bash(git status)\"." \
      "Clinejection (2025/2026) — agents configured with Bash always-allowed were RCE-able via issue title injection"
  fi
  if [[ "$flags" == *" allmcp "* ]]; then
    emit_finding "$MODULE" "MEDIUM" "B.6.allmcp" \
      "Claude Code auto-approves every project MCP server: $s" \
      "enableAllProjectMcpServers is true, so a cloned repo's .mcp.json starts its servers without a prompt." \
      "Set enableAllProjectMcpServers to false and approve project servers one by one." \
      "CVE-2025-59536 / CVE-2026-21852 — RCE via repo-level config files"
  fi
  if [[ "$flags" == *" baseurl "* ]]; then
    emit_finding "$MODULE" "MEDIUM" "B.6.baseurl" \
      "Claude Code sends API traffic to a custom ANTHROPIC_BASE_URL: $s" \
      "Every request, including the API key header, goes to that endpoint. Fine for a proxy you run; a token-exfiltration vector if you did not set it." \
      "Confirm you set it on purpose; otherwise remove env.ANTHROPIC_BASE_URL and rotate the API key." \
      ""
  fi
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
