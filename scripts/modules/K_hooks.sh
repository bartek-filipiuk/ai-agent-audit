#!/usr/bin/env bash
# Module K: AI agent hooks + repository-level config audit
#
# Covers:
#   - Globally-defined Claude Code hooks (~/.claude/settings.json) that exec arbitrary commands
#   - Repository-level AI configs (.claude/, .cursor/, .windsurf/, .codeium/) — CVE-2025-59536, CVE-2026-21852
#   - Prompt-injection patterns in CLAUDE.md / AGENTS.md / .cursorrules:
#     * Zero-width / bidi-control characters (Snyk ToxicSkills)
#     * "Ignore previous instructions" / classic injection language
#     * "Skip safety / bypass approval" instructions

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="K"
log "$MODULE" "Starting AI hooks + repo config audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# ---------- K.1: Global Claude Code / Cursor hooks ----------
GLOBAL_AGENT_SETTINGS=(
  "$HOME/.claude/settings.json"
  "$HOME/.claude/settings.local.json"
  "/etc/claude-code/managed-settings.json"
  "$HOME/.gemini/settings.json"
)
for s in "${GLOBAL_AGENT_SETTINGS[@]}"; do
  [[ -f "$s" ]] || continue
  if grep -q '"hooks"' "$s" 2>/dev/null; then
    hook_lines=""
    while IFS=: read -r n _; do
      hook_lines+="$(untrusted_snippet "$s" "$n")"$'\n'
    done < <(grep -nE '"command"[[:space:]]*:[[:space:]]*"[^"]+"' "$s" 2>/dev/null | head -5)
    emit_finding "$MODULE" "HIGH" "K.1.cc.hooks" \
      "Global agent hooks defined: $s" \
      "First commands found:"$'\n'"${hook_lines:-(no command field directly visible)}" \
      "Each hook runs with the user's full privileges on every matching event. Audit each one. If a malicious prompt can trigger a hook (e.g. UserPromptSubmit), that's effectively RCE. Consider running: jq '.hooks' \"$s\" to inspect structure." \
      "CVE-2025-59536 / CVE-2026-21852 — hooks abused for RCE via untrusted prompts/repos"
  fi
done

# Hooks shipped by installed Claude Code plugins. Aggregated into one finding: they come
# from plugins you chose to install, and one HIGH per plugin would drown the report.
plugin_hooks=()
if [[ -d "$HOME/.claude/plugins" ]]; then
  while IFS= read -r f; do
    [[ -n "$f" ]] && plugin_hooks+=("$f")
  done < <(find "$HOME/.claude/plugins" -path '*/hooks/hooks.json' -not -path '*/node_modules/*' 2>/dev/null)
fi
if [[ "${#plugin_hooks[@]}" -gt 0 ]]; then
  emit_finding "$MODULE" "MEDIUM" "K.1.plugin.hooks" \
    "${#plugin_hooks[@]} installed plugin hook file(s) run commands on agent events" \
    "First files:"$'\n'"$(printf '%s\n' "${plugin_hooks[@]}" | head -10)" \
    "Plugin hooks run with your privileges on every matching event. Review each: jq . <file>. Uninstall plugins you do not use (/plugin in Claude Code), and prefer plugins from sources you trust." \
    "CVE-2025-59536 / CVE-2026-21852 — hooks abused for RCE"
fi

# ---------- K.2: Repo-level AI config files in workspace ----------
# These files are auto-loaded when an agent runs in the directory. Treat untrusted repos
# (anything cloned recently, anything with foreign remote.origin.url) as suspect.
declare -a REPO_CFG_GLOBS=(
  ".claude/settings.json"
  ".claude/settings.local.json"
  ".cursor/settings.json"
  ".cursor/rules"
  ".windsurf/settings.json"
  ".codeium/config.json"
  "CLAUDE.md"
  ".cursorrules"
  ".clinerules"
  "AGENTS.md"
  "GEMINI.md"
  ".windsurfrules"
  ".github/copilot-instructions.md"
)

repo_cfg_total=0
risky_paths=()    # files with hooks/commands/allowedTools — emit per-file (HIGH)
plain_paths=()    # plain CLAUDE.md / .cursorrules etc. — aggregated (MEDIUM)

for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r found; do
    [[ -z "$found" ]] && continue
    repo_cfg_total=$((repo_cfg_total+1))

    # Executable or trust-widening content. Claude Code settings are judged by their risk
    # flags (hooks, bypass mode, Bash allow-all, ANTHROPIC_BASE_URL, apiKeyHelper,
    # auto-approved MCP): a plain allow-list of specific commands is what "Always allow"
    # writes into every project's settings.local.json and is not, by itself, a risk.
    risky=0
    case "$found" in
      */.claude/settings.json|*/.claude/settings.local.json)
        [[ -n "$(claude_settings_flags "$found")" ]] && risky=1 ;;
      *)
        grep -qE '"hooks"|"command"[[:space:]]*:|allowedTools|alwaysAllow' "$found" 2>/dev/null && risky=1 ;;
    esac
    if [[ "$risky" -eq 1 ]]; then
      risky_paths+=("$found")
    else
      plain_paths+=("$found")
    fi
  done < <(
    for cfg in "${REPO_CFG_GLOBS[@]}"; do
      dev_find "$p" 5 -path "*/$cfg"
    done | sort -u
  )
done

# Per-file HIGH findings for risky configs (these contain actual executable hooks/tools)
for found in "${risky_paths[@]}"; do
  repo_root="$found"
  while [[ "$repo_root" != "/" && "$repo_root" != "$HOME" ]]; do
    repo_root=$(dirname "$repo_root")
    [[ -d "$repo_root/.git" ]] && break
  done
  if [[ -d "$repo_root/.git" ]]; then
    # Read .git/config as a file: no git process inside a possibly untrusted repo.
    remote=$(sed -n '/^\[remote "origin"\]/,/^\[/{s/^[[:space:]]*url[[:space:]]*=[[:space:]]*//p;}' "$repo_root/.git/config" 2>/dev/null | head -1)
    remote=$(redact_secrets_in_text "${remote:-(no remote)}")
  else
    remote="(no enclosing git repo found)"
  fi
  flags=$(claude_settings_flags "$found")
  emit_finding "$MODULE" "HIGH" "K.2.risky" \
    "Repo-level AI config with hooks / permissions / env overrides: $found" \
    "Origin: $remote. Risk flags: ${flags:-hooks or commands}. These run with full agent privileges, or widen what the agent may do, in this repo." \
    "Inspect: cat \"$found\". For untrusted/cloned repos, run agents with --no-config or in a devcontainer. Verify each hook command before allowing the agent to run here." \
    "CVE-2025-59536 / CVE-2026-21852 — RCE via repo-level config files"
done

# Aggregated MEDIUM finding for plain rules files (CLAUDE.md / AGENTS.md / .cursorrules)
if [[ "${#plain_paths[@]}" -gt 0 ]]; then
  # Sample list (first 15 for readability)
  sample=""
  for i in "${!plain_paths[@]}"; do
    [[ "$i" -ge 15 ]] && break
    sample="$sample- ${plain_paths[$i]}"$'\n'
  done
  remainder=$(( ${#plain_paths[@]} - 15 ))
  [[ "$remainder" -gt 0 ]] && sample="$sample- ... and $remainder more"

  emit_finding "$MODULE" "MEDIUM" "K.2.plain" \
    "${#plain_paths[@]} repo-level rules file(s) (CLAUDE.md / .cursorrules / AGENTS.md) across workspace" \
    "Each is auto-loaded into agent context when running there. Each is also a potential prompt-injection vector when the repo is untrusted."$'\n\n'"First entries:"$'\n'"$sample" \
    "Cloned/external repos: review the rules files before running an agent in them. Pay attention to anything in K.3 findings (zero-width chars, injection language). Trusted repos: still review on every git pull (rules can change adversarially over time)." \
    "CVE-2025-59536 / CVE-2026-21852 + Snyk ToxicSkills (Feb 2026)"
fi

if [[ "$repo_cfg_total" -gt 0 ]]; then
  emit_finding "$MODULE" "INFO" "K.2.summary" \
    "$repo_cfg_total repo-level AI config file(s) total: ${#risky_paths[@]} with hooks/tools (per-file findings above), ${#plain_paths[@]} plain rules (aggregated)" \
    "Each is auto-loaded by the corresponding AI agent when working in that repo." \
    "" ""
fi

# ---------- K.3: Prompt-injection patterns in agent rules files ----------
# Rules files, plus repo-level agent and command definitions (.claude/agents/*.md,
# .claude/commands/*.md), which are loaded into the agent's context the same way.
inj_files=()
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r f; do
    [[ -n "$f" ]] && inj_files+=("$f")
  done < <(dev_find "$p" 5 -type f \
    \( -name 'CLAUDE.md' -o -name 'GEMINI.md' -o -name 'AGENTS.md' -o -name '.cursorrules' \
       -o -name '.clinerules' -o -name '.windsurfrules' -o -name 'copilot-instructions.md' \
       -o -path '*/.claude/agents/*.md' -o -path '*/.claude/commands/*.md' \))
done

# Also inspect global rules locations
for f in "$HOME/.claude/CLAUDE.md" "$HOME/CLAUDE.md" "$HOME/.gemini/GEMINI.md" "$HOME/.codex/AGENTS.md"; do
  [[ -f "$f" ]] && inj_files+=("$f")
done

for f in "${inj_files[@]}"; do
  [[ -r "$f" ]] || continue

  # Zero-width / bidi-control chars (pattern in common.sh; U+200D emoji joiner excluded)
  if LC_ALL=C grep -qE "$ZWBIDI_RE" "$f" 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "K.3.bidi" \
      "Zero-width / bidi-control chars in agent rules: $f" \
      "Invisible Unicode chars are a known prompt-injection technique — humans don't see the hidden instructions, the agent does." \
      "Inspect bytes: hexdump -C \"$f\" | grep -E 'e2 80 (8b|8c|8e|8f|aa|ab|ac|ad|ae)|e2 81 (a[0-4]|a[6-9])'. Strip with: perl -CSD -i -pe 's/[\\x{200B}\\x{200C}\\x{200E}\\x{200F}\\x{202A}-\\x{202E}\\x{2060}-\\x{2064}\\x{2066}-\\x{2069}]//g' \"$f\"" \
      "Snyk ToxicSkills (Feb 2026) — invisible chars used in 1467 malicious skill payloads on ClawHub"
  fi

  # Classic injection language
  n=$(grep -niE "$INJECTION_RE" "$f" 2>/dev/null | head -1 | cut -d: -f1)
  if [[ -n "$n" ]]; then
    emit_finding "$MODULE" "MEDIUM" "K.3.injection" \
      "Prompt-injection text in agent rules: $f" \
      "Line: $(untrusted_snippet "$f" "$n")" \
      "Review whether this is intentional. Injection-style language in rules conditions the agent to follow override patterns even when source is untrusted. Remove or rewrite as positive instruction." \
      "Standard prompt-injection signature"
  fi

  # "Skip / bypass safety" instructions
  n=$(grep -niE "$BYPASS_RE" "$f" 2>/dev/null | head -1 | cut -d: -f1)
  if [[ -n "$n" ]]; then
    emit_finding "$MODULE" "HIGH" "K.3.bypass" \
      "Rules file weakens agent safety: $f" \
      "Line: $(untrusted_snippet "$f" "$n")" \
      "Review and remove instructions that bypass confirmations. The agent should always require approval for destructive ops, regardless of what rules say." \
      "Replit / Gemini / PocketOS — every documented incident involved bypass-style instructions in rules"
  fi

  # Rules File Backdoor: instructions hidden in HTML comments (invisible in rendered Markdown)
  n=$(grep -nE '<!--' "$f" 2>/dev/null | grep -iE "$INJECTION_RE|$BYPASS_RE|$NETEXEC_RE|$EXFIL_RE" | head -1 | cut -d: -f1)
  if [[ -n "$n" ]]; then
    emit_finding "$MODULE" "HIGH" "K.3.hidden" \
      "Instructions hidden in an HTML comment in agent rules: $f" \
      "Line: $(untrusted_snippet "$f" "$n")" \
      "HTML comments do not render in Markdown previews but reach the agent verbatim. Remove the comment and review who added it (git log -p -- \"$f\")." \
      "Rules File Backdoor (Pillar Security, 2025) — hidden instructions in rules files"
  fi
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
