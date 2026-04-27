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
> "$FINDINGS_DIR/$MODULE.jsonl"

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
  done < <(find "$p" -maxdepth 5 -type d -name 'skills' -path '*/.claude/skills' -not -path '*/node_modules/*' 2>/dev/null)
done

UTF_ZWBIDI=$'\xe2\x80[\x8b\x8c\x8d\x8e\x8f\xaa\xab\xac\xad\xae]\|\xe2\x81[\xa0\xa1\xa2\xa3\xa4]'

total_skills=0
recent_skills=0

for d in "${SKILL_DIRS[@]}"; do
  [[ -d "$d" ]] || continue

  # Each skill is typically a subdirectory with a SKILL.md (or plugin.json)
  while IFS= read -r skill_dir; do
    [[ -z "$skill_dir" ]] && continue
    total_skills=$((total_skills+1))
    skill_name=$(basename "$skill_dir")
    skill_md="$skill_dir/SKILL.md"
    [[ -f "$skill_md" ]] || skill_md=$(find "$skill_dir" -maxdepth 1 -iname 'SKILL.md' -type f 2>/dev/null | head -1)

    # mtime / age
    mtime=$(file_mtime_unix "$skill_dir")
    if [[ -n "$mtime" ]]; then
      age_days=$(( ($(date +%s) - mtime) / 86400 ))
    else
      age_days=-1
    fi

    if [[ "$age_days" -ge 0 && "$age_days" -lt 30 ]]; then
      recent_skills=$((recent_skills+1))
      emit_finding "$MODULE" "MEDIUM" "L.1.recent" \
        "Recently installed agent skill: $skill_name (age: $age_days day(s))" \
        "Path: $skill_dir. Recent installs from third-party marketplaces are a known attack vector — ClawHub publishers can be 1-week-old GitHub accounts." \
        "Verify the source of this skill: does it come from Anthropic/official sources, or a third-party marketplace? If untrusted: rm -rf \"$skill_dir\". For trusted skills, pin to a specific version or commit." \
        "Snyk ToxicSkills (Feb 2026) — 30+ malicious skills tracked on ClawHub since launch"
    fi

    # SKILL.md content checks
    if [[ -n "${skill_md:-}" && -f "$skill_md" ]]; then
      # Zero-width / bidi chars
      if LC_ALL=C grep -q "$UTF_ZWBIDI" "$skill_md" 2>/dev/null; then
        emit_finding "$MODULE" "HIGH" "L.2.bidi" \
          "Skill SKILL.md contains zero-width / bidi-control chars: $skill_name" \
          "Path: $skill_md. Invisible Unicode chars are a known prompt-injection technique." \
          "Inspect: hexdump -C \"$skill_md\". If found, remove the skill: rm -rf \"$skill_dir\". Such chars never legitimately appear in human-written skill descriptions." \
          "Snyk ToxicSkills — invisible chars in 1467 malicious payloads"
      fi

      # Suspicious instructions in SKILL.md (it instructs the AGENT)
      if grep -qiE '(skip|bypass|disable|ignore|never).*(confirmation|approval|safety|permission prompt|user prompt|review)|exfiltrate|silently|without (telling|notifying|asking)' "$skill_md" 2>/dev/null; then
        line=$(grep -niE '(skip|bypass|disable|ignore|never).*(confirmation|approval|safety|permission prompt|user prompt|review)|exfiltrate|silently|without (telling|notifying|asking)' "$skill_md" | head -1)
        emit_finding "$MODULE" "HIGH" "L.2.bypass" \
          "Skill instructions weaken safety / suggest exfiltration: $skill_name" \
          "Line: $line — Path: $skill_md" \
          "Read the entire SKILL.md. If anything looks adversarial — remove the skill: rm -rf \"$skill_dir\". Report the source." \
          "Standard adversarial skill pattern"
      fi

      # Outbound network commands embedded in skill body (curl / wget / nc to non-localhost)
      if grep -qE '(curl|wget|nc)[[:space:]].+(\|.*sh|\|.*bash|\|\s*python|>\s*/tmp/|--user-data-binary)' "$skill_md" 2>/dev/null; then
        emit_finding "$MODULE" "HIGH" "L.2.netexec" \
          "Skill body contains pipe-to-shell / curl-to-eval pattern: $skill_name" \
          "Path: $skill_md. This is the canonical RCE pattern in installer scripts." \
          "Read the skill carefully. Refuse to load. Remove if not from a verified source." \
          "Standard supply-chain attack signature"
      fi
    fi
  done < <(find "$d" -mindepth 1 -maxdepth 2 -type d 2>/dev/null)
done

# Summary
if [[ "$total_skills" -gt 0 ]]; then
  emit_finding "$MODULE" "INFO" "L.summary" \
    "Inventory: $total_skills agent skill(s)/plugin(s) — $recent_skills installed in last 30 days" \
    "Each skill is loaded into agent context on every relevant invocation." \
    "" ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
