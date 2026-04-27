#!/usr/bin/env bash
# Aggregates per-module findings JSONL files into:
#   - audit-report.json (single JSON array)
#   - audit-report.md (human-readable)

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

OUT_JSON="$AUDIT_DIR/audit-report.json"
OUT_MD="$AUDIT_DIR/audit-report.md"

# ---------- JSON output ----------
{
  echo '{'
  echo '  "generated_at": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",'
  echo '  "host_os": "'"$OS"'",'
  echo '  "findings": ['
  first=1
  for f in "$FINDINGS_DIR"/*.jsonl; do
    [[ -f "$f" ]] || continue
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if [[ $first -eq 1 ]]; then
        first=0
      else
        echo ','
      fi
      printf '    %s' "$line"
    done < "$f"
  done
  echo
  echo '  ]'
  echo '}'
} > "$OUT_JSON"

# ---------- Counts by severity ----------
count_sev() {
  local sev="$1"
  grep -hoE '"severity":"'"$sev"'"' "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' '
}

CRIT=$(count_sev "CRITICAL")
HIGH=$(count_sev "HIGH")
MED=$(count_sev "MEDIUM")
LOW=$(count_sev "LOW")
INFO=$(count_sev "INFO")
TOTAL=$((CRIT + HIGH + MED + LOW + INFO))

# ---------- Markdown report ----------
{
  echo "# AI Agent Audit Report"
  echo
  echo "Generated: $(date)"
  echo
  echo "Host OS: \`$OS\`"
  echo
  echo "## Summary"
  echo
  echo "| Severity | Count |"
  echo "|----------|------:|"
  echo "| 🔴 CRITICAL | $CRIT |"
  echo "| 🟠 HIGH | $HIGH |"
  echo "| 🟡 MEDIUM | $MED |"
  echo "| 🟢 LOW | $LOW |"
  echo "| ℹ️ INFO | $INFO |"
  echo "| **Total** | **$TOTAL** |"
  echo
  if [[ $CRIT -gt 0 ]]; then
    echo "> ⚠️ **$CRIT critical issue(s) found.** Address these first — they enable documented incident classes."
    echo
  fi

  # Render findings by severity
  for sev in CRITICAL HIGH MEDIUM LOW INFO; do
    local_count=$(count_sev "$sev")
    [[ "$local_count" -eq 0 ]] && continue

    case "$sev" in
      CRITICAL) emoji="🔴" ;;
      HIGH)     emoji="🟠" ;;
      MEDIUM)   emoji="🟡" ;;
      LOW)      emoji="🟢" ;;
      INFO)     emoji="ℹ️" ;;
    esac

    echo
    echo "## $emoji $sev findings ($local_count)"
    echo

    # Iterate through all findings of this severity, in module order
    for module_letter in A B C D E F G H I J; do
      f="$FINDINGS_DIR/$module_letter.jsonl"
      [[ -f "$f" ]] || continue
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if echo "$line" | grep -q '"severity":"'"$sev"'"'; then
          # Extract fields with simple sed (avoid jq dependency)
          id=$(echo "$line"      | sed -nE 's/.*"id":"([^"]*)".*/\1/p')
          title=$(echo "$line"   | sed -nE 's/.*"title":"([^"]*)".*/\1/p')
          evidence=$(echo "$line"| sed -nE 's/.*"evidence":"([^"]*)".*/\1/p')
          remed=$(echo "$line"   | sed -nE 's/.*"remediation":"([^"]*)".*/\1/p')
          incident=$(echo "$line"| sed -nE 's/.*"incident":"([^"]*)".*/\1/p')

          # Unescape \n
          evidence=$(printf '%b' "${evidence//\\n/$'\n'}")
          remed=$(printf '%b' "${remed//\\n/$'\n'}")

          echo "### \`[$module_letter.$id]\` $title"
          echo
          if [[ -n "$evidence" ]]; then
            echo "**Evidence:**"
            echo
            echo "$evidence" | sed 's/^/> /'
            echo
          fi
          if [[ -n "$remed" ]]; then
            echo "**Remediation:**"
            echo
            echo "$remed"
            echo
          fi
          if [[ -n "$incident" ]]; then
            echo "**Related incident:** $incident"
            echo
          fi
        fi
      done < "$f"
    done
  done

  echo
  echo "---"
  echo
  echo "## How to interpret severities"
  echo
  echo "- **CRITICAL** — directly enables a documented incident class (Nx s1ngularity-style credential exfil, PocketOS-style production deletion). Fix today."
  echo "- **HIGH** — significantly amplifies blast radius if anything goes wrong. Fix this week."
  echo "- **MEDIUM** — hygiene. Fix this month."
  echo "- **LOW** — best practice."
  echo "- **INFO** — context, no action needed."
  echo
  echo "## Useful commands after audit"
  echo
  echo '```bash'
  echo '# Re-run a specific module:'
  echo 'bash scripts/run-audit.sh --modules G'
  echo
  echo '# Inspect raw JSONL findings:'
  echo 'cat ~/.ai-agent-audit/findings/A.jsonl | jq'
  echo
  echo '# Count findings by ID across modules:'
  echo 'cat ~/.ai-agent-audit/findings/*.jsonl | jq -r .id | sort | uniq -c'
  echo '```'
} > "$OUT_MD"

log "AGG" "Report written: $OUT_MD"
log "AGG" "JSON written:   $OUT_JSON"
log "AGG" "Findings: CRITICAL=$CRIT HIGH=$HIGH MEDIUM=$MED LOW=$LOW INFO=$INFO"
