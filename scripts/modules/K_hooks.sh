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
> "$FINDINGS_DIR/$MODULE.jsonl"

# ---------- K.1: Global Claude Code / Cursor hooks ----------
GLOBAL_AGENT_SETTINGS=(
  "$HOME/.claude/settings.json"
  "$HOME/.claude/settings.local.json"
  "$HOME/.config/claude-code/settings.json"
)
for s in "${GLOBAL_AGENT_SETTINGS[@]}"; do
  [[ -f "$s" ]] || continue
  if grep -q '"hooks"' "$s" 2>/dev/null; then
    hook_lines=$(grep -nE '"command"\s*:\s*"[^"]+"' "$s" 2>/dev/null | head -5)
    emit_finding "$MODULE" "HIGH" "K.1.cc.hooks" \
      "Global agent hooks defined: $s" \
      "First commands found:\n${hook_lines:-(no command field directly visible)}" \
      "Each hook runs with the user's full privileges on every matching event. Audit each one. If a malicious prompt can trigger a hook (e.g. UserPromptSubmit), that's effectively RCE. Consider running: jq '.hooks' \"$s\" to inspect structure." \
      "CVE-2025-59536 / CVE-2026-21852 — hooks abused for RCE via untrusted prompts/repos"
  fi
done

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
  ".windsurfrules"
)

repo_cfg_total=0
risky_paths=()    # files with hooks/commands/allowedTools — emit per-file (HIGH)
plain_paths=()    # plain CLAUDE.md / .cursorrules etc. — aggregated (MEDIUM)

for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r found; do
    [[ -z "$found" ]] && continue
    repo_cfg_total=$((repo_cfg_total+1))

    if [[ -f "$found" ]] && grep -qE '"hooks"|"command"[[:space:]]*:|allowedTools|alwaysAllow' "$found" 2>/dev/null; then
      risky_paths+=("$found")
    else
      plain_paths+=("$found")
    fi
  done < <(
    for cfg in "${REPO_CFG_GLOBS[@]}"; do
      find "$p" -maxdepth 5 -path "*/$cfg" -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null
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
    remote=$(git -C "$repo_root" config --get remote.origin.url 2>/dev/null || echo "(no remote)")
  else
    remote="(no enclosing git repo found)"
  fi
  emit_finding "$MODULE" "HIGH" "K.2.risky" \
    "Repo-level AI config with hooks / allowed-tools: $found" \
    "Origin: $remote. Contains executable hooks or allowed-tools entries — runs with full agent privileges in this repo." \
    "Inspect: cat \"$found\". For untrusted/cloned repos, run agents with --no-config or in a devcontainer. Verify each hook command before allowing the agent to run here." \
    "CVE-2025-59536 / CVE-2026-21852 — RCE via repo-level config files"
done

# Aggregated MEDIUM finding for plain rules files (CLAUDE.md / AGENTS.md / .cursorrules)
if [[ "${#plain_paths[@]}" -gt 0 ]]; then
  # Sample list (first 15 for readability)
  sample=""
  for i in "${!plain_paths[@]}"; do
    [[ "$i" -ge 15 ]] && break
    sample="$sample- ${plain_paths[$i]}\n"
  done
  remainder=$(( ${#plain_paths[@]} - 15 ))
  [[ "$remainder" -gt 0 ]] && sample="$sample- ... and $remainder more"

  emit_finding "$MODULE" "MEDIUM" "K.2.plain" \
    "${#plain_paths[@]} repo-level rules file(s) (CLAUDE.md / .cursorrules / AGENTS.md) across workspace" \
    "Each is auto-loaded into agent context when running there. Each is also a potential prompt-injection vector when the repo is untrusted.\n\nFirst entries:\n$sample" \
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
# Detection runs on CLAUDE.md, AGENTS.md, .cursorrules, .clinerules, .windsurfrules.
inj_files=()
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r f; do
    [[ -n "$f" ]] && inj_files+=("$f")
  done < <(find "$p" -maxdepth 5 -type f \
    \( -name 'CLAUDE.md' -o -name '.cursorrules' -o -name '.clinerules' -o -name 'AGENTS.md' -o -name '.windsurfrules' \) \
    -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
done

# Also inspect global rules locations
[[ -f "$HOME/.claude/CLAUDE.md" ]] && inj_files+=("$HOME/.claude/CLAUDE.md")
[[ -f "$HOME/CLAUDE.md" ]] && inj_files+=("$HOME/CLAUDE.md")

# UTF-8 byte sequences for zero-width / bidi-control chars (avoids dependency on grep -P).
# U+200B–200F: e2 80 8b–8f ; U+202A–202E: e2 80 aa–ae ; U+2060–2064: e2 81 a0–a4
ZWBIDI_GREP=$'\xe2\x80[\x8b\x8c\x8d\x8e\x8f\xaa\xab\xac\xad\xae]\|\xe2\x81[\xa0\xa1\xa2\xa3\xa4]'

for f in "${inj_files[@]}"; do
  [[ -r "$f" ]] || continue

  # Zero-width / bidi-control chars
  if LC_ALL=C grep -q "$ZWBIDI_GREP" "$f" 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "K.3.bidi" \
      "Zero-width / bidi-control chars in agent rules: $f" \
      "Invisible Unicode chars are a known prompt-injection technique — humans don't see the hidden instructions, the agent does." \
      "Inspect bytes: hexdump -C \"$f\" | grep -E 'e2 80 (8b|8c|8d|8e|8f|aa|ab|ac|ad|ae)|e2 81 a[0-4]'. Strip with: perl -CSD -i -pe 's/[\\x{200B}-\\x{200F}\\x{202A}-\\x{202E}\\x{2060}-\\x{2064}]//g' \"$f\"" \
      "Snyk ToxicSkills (Feb 2026) — invisible chars used in 1467 malicious skill payloads on ClawHub"
  fi

  # Classic injection language
  if grep -qiE 'ignore (all )?(previous|prior|above|earlier) (instructions?|rules|context)|disregard (the )?(above|earlier|prior) (rules|instructions|context)|new instructions:|you are now [a-z]+' "$f" 2>/dev/null; then
    line=$(grep -niE 'ignore (all )?(previous|prior|above|earlier) (instructions?|rules|context)|disregard (the )?(above|earlier|prior) (rules|instructions|context)|new instructions:|you are now [a-z]+' "$f" | head -1)
    emit_finding "$MODULE" "MEDIUM" "K.3.injection" \
      "Prompt-injection text in agent rules: $f" \
      "Line: $line" \
      "Review whether this is intentional. Injection-style language in rules conditions the agent to follow override patterns even when source is untrusted. Remove or rewrite as positive instruction." \
      "Standard prompt-injection signature"
  fi

  # "Skip / bypass safety" patterns
  if grep -qiE '(skip|bypass|disable|ignore|never).*(confirmation|approval|safety|permission prompt|user prompt|review)' "$f" 2>/dev/null; then
    line=$(grep -niE '(skip|bypass|disable|ignore|never).*(confirmation|approval|safety|permission prompt|user prompt|review)' "$f" | head -1)
    emit_finding "$MODULE" "HIGH" "K.3.bypass" \
      "Rules file weakens agent safety: $f" \
      "Line: $line" \
      "Review and remove instructions that bypass confirmations. The agent should always require approval for destructive ops, regardless of what rules say." \
      "Replit / Gemini / PocketOS — every documented incident involved bypass-style instructions in rules"
  fi
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
