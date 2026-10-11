#!/usr/bin/env bash
# Module L: AI agent skills / plugins supply-chain audit
#
# Inventories installed skills and plugins for Claude Code / Cursor / etc., flags:
#   - Recently installed (< 30 days) — short-tenure publishers are a known attack vector
#   - SKILL.md / plugin code with prompt-injection patterns
#   - Skills loaded from sources without code signing or review (ClawHub, third-party marketplaces)
#
# Background: Snyk ToxicSkills (Feb 2026) — 36% of skills on ClawHub had prompt injection,
# 1467 malicious payloads documented. ClawHub publishing requires only a SKILL.md and a
# 1-week-old GitHub account. No code signing, no security review, no sandbox.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="L"
log "$MODULE" "Starting AI skills / plugins supply-chain audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# Locations to inspect
SKILL_DIRS=(
  "$HOME/.claude/skills"
  "$HOME/.claude/plugins"
  "$HOME/.cursor/skills"
  "$HOME/.cursor/plugins"
  "$HOME/.config/claude-code/skills"
)

# Per-project .claude/skills/
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r d; do
    [[ -n "$d" ]] && SKILL_DIRS+=("$d")
  done < <(dev_find "$p" 5 -type d -path '*/.claude/skills')
done

total_skills=0
recent_skills=0
recent_list=()

for d in "${SKILL_DIRS[@]}"; do
  [[ -d "$d" ]] || continue

  # A skill is a directory holding a SKILL.md. Enumerating every subdirectory counted
  # plugin internals (cache/, repos/, marketplaces/) as skills and missed nested ones.
  while IFS= read -r skill_md; do
    [[ -z "$skill_md" ]] && continue
    skill_dir=$(dirname "$skill_md")
    total_skills=$((total_skills+1))
    skill_name=$(basename "$skill_dir")

    # mtime / age
    mtime=$(file_mtime_unix "$skill_dir")
    if [[ -n "$mtime" ]]; then
      age_days=$(( ($(date +%s) - mtime) / 86400 ))
    else
      age_days=-1
    fi

    if [[ "$age_days" -ge 0 && "$age_days" -lt 30 ]]; then
      recent_skills=$((recent_skills+1))
      recent_list+=("$skill_dir ($age_days d)")
    fi

    # Zero-width / bidi chars (shared pattern; U+200D emoji joiner excluded)
    if LC_ALL=C grep -qE "$ZWBIDI_RE" "$skill_md" 2>/dev/null; then
      emit_finding "$MODULE" "HIGH" "L.2.bidi" \
        "Skill SKILL.md contains zero-width / bidi-control chars: $skill_name" \
        "Path: $skill_md. Invisible Unicode chars are a known prompt-injection technique." \
        "Inspect: hexdump -C \"$skill_md\". If found, remove the skill: rm -rf \"$skill_dir\". Such chars never legitimately appear in human-written skill descriptions." \
        "Snyk ToxicSkills — invisible chars in 1467 malicious payloads"
    fi

    # Instructions that switch off confirmation or hide actions from the user
    n=$(grep -niE "$BYPASS_RE|$EXFIL_RE" "$skill_md" 2>/dev/null | head -1 | cut -d: -f1)
    if [[ -n "$n" ]]; then
      emit_finding "$MODULE" "HIGH" "L.2.bypass" \
        "Skill instructions weaken safety / suggest exfiltration: $skill_name" \
        "Line: $(untrusted_snippet "$skill_md" "$n")" \
        "Read the entire SKILL.md. If anything looks adversarial — remove the skill: rm -rf \"$skill_dir\". Report the source." \
        "Standard adversarial skill pattern"
    fi

    # Download piped into a shell / interpreter
    if grep -qE "$NETEXEC_RE" "$skill_md" 2>/dev/null; then
      emit_finding "$MODULE" "HIGH" "L.2.netexec" \
        "Skill body contains pipe-to-shell / curl-to-eval pattern: $skill_name" \
        "Path: $skill_md. This is the canonical RCE pattern in installer scripts." \
        "Read the skill carefully. Refuse to load. Remove if not from a verified source." \
        "Standard supply-chain attack signature"
    fi
  done < <(find "$d" -name 'SKILL.md' -type f -not -path '*/node_modules/*' 2>/dev/null)
done

# One aggregated finding: plugin updates refresh whole skill trees, so one finding per
# skill turned every marketplace update into dozens of MEDIUMs.
if [[ "$recent_skills" -gt 0 ]]; then
  emit_finding "$MODULE" "MEDIUM" "L.1.recent" \
    "$recent_skills agent skill(s) installed or updated in the last 30 days" \
    "Most recent first-seen paths:"$'\n'"$(printf -- '- %s\n' "${recent_list[@]}" | head -15)" \
    "For each skill you did not knowingly install or update: check where it came from (Anthropic / official marketplace vs third party) and read its SKILL.md. Remove anything untrusted with rm -rf <skill dir>; pin trusted third-party skills to a commit." \
    "Snyk ToxicSkills (Feb 2026) — 30+ malicious skills tracked on ClawHub since launch"
fi

# Summary
if [[ "$total_skills" -gt 0 ]]; then
  emit_finding "$MODULE" "INFO" "L.summary" \
    "Inventory: $total_skills agent skill(s)/plugin(s) — $recent_skills installed in last 30 days" \
    "Each skill is loaded into agent context on every relevant invocation." \
    "" ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
