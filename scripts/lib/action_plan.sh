#!/usr/bin/env bash
# Generates a self-contained action plan markdown file from the current audit findings.
#
# Reads:
#   - $FINDINGS_DIR/*.jsonl   (per-module findings)
#   - $SECRETS_INVENTORY      (secrets-inventory.md, optional)
#
# Writes:
#   - $AUDIT_DIR/action-plan.md
#
# The action plan is the "do this, then this, then this" view: one ordered checklist
# grouped by urgency (TODAY / THIS WEEK / THIS MONTH), preceded by a deduplicated
# table of secrets to rotate (extracted from the secrets inventory).

generate_action_plan() {
  local out="$AUDIT_DIR/action-plan.md"

  local crit high med low info
  crit=$(grep -hoE '"severity":"CRITICAL"' "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  high=$(grep -hoE '"severity":"HIGH"'     "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  med=$( grep -hoE '"severity":"MEDIUM"'   "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  low=$( grep -hoE '"severity":"LOW"'      "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  info=$(grep -hoE '"severity":"INFO"'     "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')

  {
    echo "# Action plan"
    echo
    echo "Generated: $(date)"
    echo
    echo "Self-contained checklist extracted from \`audit-report.md\` and \`secrets-inventory.md\`. Work top-to-bottom: rotate secrets first, then CRITICAL, then HIGH. Re-run the audit when done — items you've fixed will disappear from the next plan."
    echo
    echo "## TL;DR"
    echo
    echo "| Bucket | Count | Deadline |"
    echo "|--------|------:|----------|"
    echo "| 🔴 CRITICAL | $crit | today |"
    echo "| 🟠 HIGH     | $high | this week |"
    echo "| 🟡 MEDIUM   | $med  | this month |"
    echo "| 🟢 LOW      | $low  | when convenient |"
    echo "| ℹ️ INFO     | $info | context only, no action |"
    echo

    # ----- Section: Keys to rotate (parsed from secrets-inventory.md) -----
    if [[ -f "$SECRETS_INVENTORY" ]]; then
      echo "## Keys to rotate"
      echo
      echo "Use the fingerprint (\`XXXX****YYYY (N chars)\`) to find each key in your provider's UI. The full classified table lives in \`secrets-inventory.md\`."
      echo

      # First pass — summary by type
      echo "### Summary by service"
      echo
      echo "| Service / Type | Count | Severity hint | Where to rotate |"
      echo "|----------------|------:|---------------|-----------------|"
      awk -F'|' '
        /^\| Type / { next }
        /^\|[ ]*-/ { next }
        /^\|/ {
          n=split($0, a, /\|/)
          if (n < 6) next
          type=a[2];    gsub(/^ +| +$/, "", type)
          service=a[3]; gsub(/^ +| +$/, "", service)
          rotate=a[4];  gsub(/^ +| +$/, "", rotate)
          sev=a[5];     gsub(/^ +| +$/, "", sev)
          if (type == "Type" || type == "") next
          key=type "|" service "|" rotate "|" sev
          counts[key]++
        }
        END {
          for (k in counts) printf("%d\t%s\n", counts[k], k)
        }
      ' "$SECRETS_INVENTORY" | sort -k1,1 -nr | awk -F'\t' '
        {
          n=$1
          split($2, a, /\|/)
          type=a[1]; service=a[2]; rotate=a[3]; sev=a[4]
          if (service != "") label=type " (" service ")"; else label=type
          printf("| %s | %d | %s | %s |\n", label, n, sev, rotate)
        }
      '
      echo

      # Second pass — full breakdown per source
      echo "### Full breakdown per source"
      echo
      echo "_Each row = one distinct secret to rotate. Same secret type appearing N times = N different keys (different fingerprints), each needs its own rotation._"
      echo

      awk -F'|' '
        /^## Source: / {
          if (current != "") print "" > "/dev/stderr"
          sub(/^## Source: */, "")
          gsub(/^[ \t]+|[ \t]+$/, "")
          current=$0
          printed_header=0
          print ""
          print "#### From: " current
          print ""
          next
        }
        /^\| Type / { next }
        /^\|[ ]*-/ { next }
        /^\|/ {
          n=split($0, a, /\|/)
          if (n < 6) next
          type=a[2];    gsub(/^ +| +$/, "", type)
          service=a[3]; gsub(/^ +| +$/, "", service)
          fp=a[6];      gsub(/^ +| +$/, "", fp)
          if (type == "Type" || type == "") next
          if (!printed_header) {
            print "| Service / Type | Fingerprint |"
            print "|----------------|-------------|"
            printed_header=1
          }
          if (service != "" && service != type) label=type " (" service ")"; else label=type
          printf("| %s | %s |\n", label, fp)
        }
      ' "$SECRETS_INVENTORY"
      echo
      echo "_Tip: when a row's fingerprint clearly matches a documentation example (e.g. starts with \`AKIA0000\` or \`ghp_xxxx\`), deprioritise — the audit can't distinguish example tokens from real ones._"
      echo
    fi

    # ----- Section: TODAY (CRITICAL) -----
    if [[ "$crit" -gt 0 ]]; then
      echo "## 🔴 TODAY — Critical findings ($crit)"
      echo
      echo "These directly enable a documented incident class. Do these first."
      echo
      _action_plan_render_findings "CRITICAL"
    fi

    # ----- Section: THIS WEEK (HIGH) -----
    if [[ "$high" -gt 0 ]]; then
      echo "## 🟠 THIS WEEK — High findings ($high)"
      echo
      echo "Significantly amplify blast radius. Do within 7 days."
      echo
      _action_plan_render_findings "HIGH"
    fi

    # ----- Section: THIS MONTH (MEDIUM, condensed) -----
    if [[ "$med" -gt 0 ]]; then
      echo "## 🟡 THIS MONTH — Medium findings ($med)"
      echo
      echo "Hygiene issues. Walk through these once a month."
      echo
      _action_plan_render_findings_condensed "MEDIUM"
    fi

    # ----- Section: Workflow changes -----
    cat <<'HABITS'
## Workflow changes (apply going forward, regardless of current findings)

These are habit changes, not fixes — they keep findings from coming back.

- **Never paste secrets into agent chat.** Use environment variables (`process.env.X`) or 1Password references (`op://vault/item/field`). Anything pasted into Claude Code, Cursor, or Aider lands in a session JSONL/SQLite forever, and is reloaded into agent context on every wake.
- **Every new SSH key gets a passphrase immediately** at `ssh-keygen` time. Use `ssh-add -t 3600 <key>` instead of plain `ssh-add` so the key is unlocked for one hour, not until logout.
- **AWS — SSO only.** Run `aws configure sso` once, then `aws sso login` for every working session. No long-lived `AKIA...` IAM keys on disk.
- **Before cloning an unknown repo and running an agent in it,** inspect the repo-level configs first: `cat .claude/settings.json .cursor/settings.json CLAUDE.md AGENTS.md 2>/dev/null`. Repo-level configs are RCE vectors (CVE-2025-59536, CVE-2026-21852).
- **MCP servers — pin every version,** or install globally with an audited version and reference the absolute binary path. Never use unpinned `npx` or `uvx` in MCP configs.
- **GitHub tokens — least privilege per token.** Default `gh auth refresh -s repo,read:org`. Destructive scopes (`delete_repo`, `admin:org`, `workflow`, `write:packages`) only on a separate token loaded ad hoc.
- **npm publish — OIDC, not static tokens.** For CI use GitHub Actions with `permissions: id-token: write` and `npm publish --provenance`. Remove static tokens from `~/.npmrc`.

## Re-run

Re-run this audit weekly while burning down the list:

```bash
bash scripts/run-audit.sh
jq -r .severity ~/.ai-agent-audit/findings/*.jsonl | sort | uniq -c
```

Each item you fix should disappear from the next `action-plan.md`. If it doesn't, the fix didn't take.
HABITS

  } > "$out"
}

# Render every finding of a given severity as a heading + action block.
_action_plan_render_findings() {
  local sev="$1"
  local n=0
  for module_letter in A B C D E F G H I J K L M N P; do
    local f="$FINDINGS_DIR/$module_letter.jsonl"
    [[ -f "$f" ]] || continue
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      printf '%s' "$line" | grep -q "\"severity\":\"$sev\"" || continue
      n=$((n+1))
      local id title remed incident
      id=$(json_decode_field "$line" "id")
      title=$(json_decode_field "$line" "title")
      remed=$(json_decode_field "$line" "remediation")
      incident=$(json_decode_field "$line" "incident")

      printf '### %d. %s\n\n' "$n" "$title"
      printf '_id: `[%s.%s]`_\n\n' "$module_letter" "$id"
      if [[ -n "$remed" ]]; then
        printf '**Action:**\n\n'
        printf '%s\n\n' "$remed"
      fi
      if [[ -n "$incident" ]]; then
        printf '_Why it matters: %s_\n\n' "$incident"
      fi
    done < "$f"
  done
}

# Render a condensed list (one bullet per finding) — used for MEDIUM where full
# remediation per item would drown the page.
_action_plan_render_findings_condensed() {
  local sev="$1"
  for module_letter in A B C D E F G H I J K L M N P; do
    local f="$FINDINGS_DIR/$module_letter.jsonl"
    [[ -f "$f" ]] || continue
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      printf '%s' "$line" | grep -q "\"severity\":\"$sev\"" || continue
      local id title remed
      id=$(json_decode_field "$line" "id")
      title=$(json_decode_field "$line" "title")
      remed=$(json_decode_field "$line" "remediation")
      # Take first line and cap at 200 chars (avoid `awk -F'. '` — its regex separator
      # explodes on any char-space pair, mangling lines like "Pin versions" → "Pi").
      local short
      short=$(printf '%s' "$remed" | head -n 1 | cut -c 1-200)
      # Use printf -- to stop option parsing; remediation can start with `-`.
      printf -- '- **%s** — %s _(`[%s.%s]`)_\n' "$title" "$short" "$module_letter" "$id"
    done < "$f"
  done
  printf '\n'
}

export -f generate_action_plan _action_plan_render_findings _action_plan_render_findings_condensed
