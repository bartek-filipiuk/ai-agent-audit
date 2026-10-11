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
  installed_tools+=("Cursor IDE")
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
