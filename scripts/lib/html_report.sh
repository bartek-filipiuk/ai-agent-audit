#!/usr/bin/env bash
# Generates a self-contained HTML audit report with cyberpunk/matrix theme.
# All CSS + ASCII art inlined; no external assets. Designed for auto-open via
# xdg-open / open at the end of run-audit.sh.
#
# Inputs:
#   $FINDINGS_DIR/*.jsonl
#   $SECRETS_INVENTORY (optional)
# Output:
#   $AUDIT_DIR/audit-report.html

# ---------- Security scoring (v2) ----------
#
# Algorithm (start at 100):
#   - 5    per CRITICAL
#   - 2.5  per HIGH                            (CVSS-aligned — HIGH ≈ 50% of CRITICAL)
#   - 0.3  per MEDIUM
#   - 0.05 per LOW
#   - 1    per 15 distinct classified secrets in inventory (capped at -15)
#   - 10   COMPOUND penalty if the host is a supply-chain distributor:
#          (MCP server launched via unpinned npx) AND
#          (npm publish-capable token OR GitHub PAT with workflow/admin scope)
#   - floor at 0
#
# The compound penalty captures something the per-finding totals miss: when a
# machine has both "I run untrusted code at every agent invocation" (npx mcp)
# and "I publish packages others install" (npm/gh writes), a single trojaned
# upstream can take down the entire user base — not just this host.
#
# Grades:
#    90-100  S  "Hardened"           (rare — full hygiene)
#    80-89   A  "Solid"
#    70-79   B  "OK-ish"
#    60-69   C  "Concerning"
#    50-59   D  "At Risk"
#    30-49   E  "Critical Exposure"
#     0-29   F  "Pwned-Ready"
#
# This is intentionally pessimistic — a developer machine should score ~70+
# and a hardened one ~90+. Anything below 50 is a "rotate everything" zone.
compute_security_score() {
  local crit="$1" high="$2" med="$3" low="$4" secrets="$5" compound="${6:-0}"
  awk -v c="$crit" -v h="$high" -v m="$med" -v l="$low" -v s="$secrets" -v cp="$compound" '
    BEGIN {
      score = 100 - 5*c - 2.5*h - 0.3*m - 0.05*l
      sp = s / 15
      if (sp > 15) sp = 15
      score -= sp
      if (cp == 1) score -= 10
      if (score < 0) score = 0
      printf "%d", score
    }'
}

compute_grade() {
  local s="$1"
  if   (( s >= 90 )); then printf 'S\tHardened'
  elif (( s >= 80 )); then printf 'A\tSolid'
  elif (( s >= 70 )); then printf 'B\tOK-ish'
  elif (( s >= 60 )); then printf 'C\tConcerning'
  elif (( s >= 50 )); then printf 'D\tAt Risk'
  elif (( s >= 30 )); then printf 'E\tCritical Exposure'
  else                    printf 'F\tPwned-Ready'
  fi
}

compute_grade_class() {
  local s="$1"
  if   (( s >= 80 )); then printf 'grade-a'
  elif (( s >= 60 )); then printf 'grade-b'
  elif (( s >= 40 )); then printf 'grade-c'
  elif (( s >= 20 )); then printf 'grade-d'
  else                    printf 'grade-f'
  fi
}

# ---------- HTML escaping ----------
html_escape() {
  printf '%s' "${1:-}" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e "s/'/\\&#39;/g" -e 's/"/\&quot;/g'
}

# ---------- Render a finding card ----------
_html_render_finding() {
  local module="$1" line="$2" sev_class="$3"
  local id title evidence remed incident
  id=$(json_decode_field "$line" "id")
  title=$(json_decode_field "$line" "title")
  evidence=$(json_decode_field "$line" "evidence")
  remed=$(json_decode_field "$line" "remediation")
  incident=$(json_decode_field "$line" "incident")

  local id_h title_h evidence_h remed_h incident_h
  id_h=$(html_escape "$id")
  title_h=$(html_escape "$title")
  evidence_h=$(html_escape "$evidence")
  remed_h=$(html_escape "$remed")
  incident_h=$(html_escape "$incident")

  printf '<details class="finding %s">' "$sev_class"
  printf '<summary><span class="bug-id">[%s.%s]</span> %s</summary>' "$module" "$id_h" "$title_h"
  printf '<div class="finding-body">'
  if [[ -n "$evidence" ]]; then
    printf '<div class="block evidence"><span class="lbl">EVIDENCE //</span><pre>%s</pre></div>' "$evidence_h"
  fi
  if [[ -n "$remed" ]]; then
    printf '<div class="block fix"><span class="lbl">FIX //</span><pre>%s</pre></div>' "$remed_h"
  fi
  if [[ -n "$incident" ]]; then
    printf '<div class="block incident"><span class="lbl">RELATED INCIDENT //</span> %s</div>' "$incident_h"
  fi
  printf '</div></details>'
}

# ---------- Render all findings of a given severity ----------
_html_render_findings_for_sev() {
  local sev="$1" sev_class="$2"
  for module_letter in A B C D E F G H I J K L M N P; do
    local f="$FINDINGS_DIR/$module_letter.jsonl"
    [[ -f "$f" ]] || continue
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      printf '%s' "$line" | grep -q "\"severity\":\"$sev\"" || continue
      _html_render_finding "$module_letter" "$line" "$sev_class"
    done < "$f"
  done
}

# ---------- Parse secrets-inventory.md and emit a per-type summary ----------
# Output is a sequence of <tr> rows for the summary table.
_html_secrets_summary_rows() {
  [[ -f "$SECRETS_INVENTORY" ]] || return
  awk -F'|' '
    /^\| Type / { next }
    /^\|[ ]*-/ { next }
    /^\|/ {
      n = split($0, a, /\|/)
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
      sev_class = "sev-" tolower(sev)
      gsub(/&/, "\\&amp;", type); gsub(/</, "\\&lt;", type); gsub(/>/, "\\&gt;", type)
      gsub(/&/, "\\&amp;", service); gsub(/</, "\\&lt;", service); gsub(/>/, "\\&gt;", service)
      gsub(/&/, "\\&amp;", rotate); gsub(/</, "\\&lt;", rotate); gsub(/>/, "\\&gt;", rotate)
      printf("<tr><td class=\"count\">%d</td><td>%s <span class=\"muted\">(%s)</span></td><td><span class=\"badge %s\">%s</span></td><td>%s</td></tr>\n",
             n, type, service, sev_class, sev, rotate)
    }
  '
}

# Per-source breakdown rows for collapsible sections
_html_secrets_per_source() {
  [[ -f "$SECRETS_INVENTORY" ]] || return
  awk -F'|' '
    /^## Source: / {
      sub(/^## Source: */, "")
      gsub(/^[ \t]+|[ \t]+$/, "")
      if (current != "") print "</tbody></table></details>"
      current=$0
      gsub(/&/, "\\&amp;", current); gsub(/</, "\\&lt;", current); gsub(/>/, "\\&gt;", current)
      printf("<details class=\"src-block\"><summary><span class=\"src-arrow\">▶</span> %s</summary><table class=\"secrets-table\"><thead><tr><th>Type / Service</th><th>Fingerprint (redacted)</th></tr></thead><tbody>", current)
      next
    }
    /^\| Type / { next }
    /^\|[ ]*-/ { next }
    /^\|/ {
      n = split($0, a, /\|/)
      if (n < 6) next
      type=a[2];    gsub(/^ +| +$/, "", type)
      service=a[3]; gsub(/^ +| +$/, "", service)
      fp=a[6];      gsub(/^ +| +$/, "", fp)
      if (type == "Type" || type == "") next
      gsub(/&/, "\\&amp;", type); gsub(/</, "\\&lt;", type); gsub(/>/, "\\&gt;", type)
      gsub(/&/, "\\&amp;", service); gsub(/</, "\\&lt;", service); gsub(/>/, "\\&gt;", service)
      gsub(/&/, "\\&amp;", fp); gsub(/</, "\\&lt;", fp); gsub(/>/, "\\&gt;", fp)
      printf("<tr><td>%s <span class=\"muted\">(%s)</span></td><td><code class=\"fp\">%s</code></td></tr>\n", type, service, fp)
    }
    END {
      if (current != "") print "</tbody></table></details>"
    }
  ' "$SECRETS_INVENTORY"
}

# Headline diagnosis text — one liner that matches the score
_html_diagnosis() {
  local s="$1"
  if   (( s >= 90 )); then echo "System is hardened. Keep doing what you're doing — and re-run weekly to detect drift."
  elif (( s >= 80 )); then echo "Mostly solid. A few weak spots remain but nothing immediately exploitable."
  elif (( s >= 70 )); then echo "Functional baseline. Some hygiene work needed, but no incident-class exposure."
  elif (( s >= 60 )); then echo "Concerning surface area. The issues compound — fix CRITICAL within the day, HIGH within the week."
  elif (( s >= 50 )); then echo "At risk. A trojaned dependency or untrusted clone could trigger an incident."
  elif (( s >= 30 )); then echo "Critical exposure. Multiple Nx-class vectors are pre-loaded — rotate broadly, fix the alias today."
  else                    echo "Pwned-Ready. One malicious npm postinstall away from full credential exfil. Treat the machine as if it's already compromised."
  fi
}

# ---------- Main HTML generator ----------
generate_html_report() {
  local out="$AUDIT_DIR/audit-report.html"

  local crit high med low info total
  crit=$(grep -hoE '"severity":"CRITICAL"' "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  high=$(grep -hoE '"severity":"HIGH"'     "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  med=$( grep -hoE '"severity":"MEDIUM"'   "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  low=$( grep -hoE '"severity":"LOW"'      "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  info=$(grep -hoE '"severity":"INFO"'     "$FINDINGS_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')
  total=$((crit + high + med + low + info))

  # Distinct classified secrets count (table rows in inventory minus header rows)
  local secrets=0
  if [[ -f "$SECRETS_INVENTORY" ]]; then
    secrets=$(grep -cE '^\| [A-Za-z]' "$SECRETS_INVENTORY" 2>/dev/null) || secrets=0
    # Subtract one header row per "## Source:" block
    local source_blocks
    source_blocks=$(grep -c '^## Source:' "$SECRETS_INVENTORY" 2>/dev/null) || source_blocks=0
    secrets=$((secrets - source_blocks))
    [[ $secrets -lt 0 ]] && secrets=0
  fi

  local score grade_full grade_letter grade_label grade_class diagnosis
  score=$(compute_security_score "$crit" "$high" "$med" "$low" "$secrets")
  grade_full=$(compute_grade "$score")
  grade_letter="${grade_full%%$'\t'*}"
  grade_label="${grade_full##*$'\t'}"
  grade_class=$(compute_grade_class "$score")
  diagnosis=$(_html_diagnosis "$score")

  local hostname_v
  hostname_v=$(hostname 2>/dev/null || echo "unknown-host")
  hostname_v=$(html_escape "$hostname_v")

  local generated
  generated=$(date)

  # Begin HTML
  cat > "$out" <<HTML_HEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI Agent Audit — ${hostname_v}</title>
<style>
:root {
  --bg: #050608;
  --bg-2: #0c1014;
  --bg-3: #141a22;
  --text: #c8d3da;
  --neon: #00ff41;
  --neon-soft: #00b832;
  --red: #ff2147;
  --orange: #ff8c00;
  --amber: #ffb700;
  --cyan: #00f0ff;
  --grey: #5a6671;
  --grid: rgba(0, 255, 65, 0.04);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Courier New', monospace;
  font-size: 14px;
  line-height: 1.55;
  min-height: 100vh;
  background-image:
    linear-gradient(var(--grid) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid) 1px, transparent 1px);
  background-size: 32px 32px;
}
/* CRT scanlines overlay */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(0deg,
    rgba(0,0,0,0.18), rgba(0,0,0,0.18) 1px,
    transparent 1px, transparent 3px);
  pointer-events: none;
  z-index: 9999;
  mix-blend-mode: multiply;
}
/* Vignette */
body::after {
  content: '';
  position: fixed;
  inset: 0;
  background: radial-gradient(ellipse at center, transparent 50%, rgba(0,0,0,0.7) 100%);
  pointer-events: none;
  z-index: 9998;
}
.wrapper {
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px 24px 96px;
  position: relative;
  z-index: 1;
}
.banner-wrap {
  text-align: center;
  margin: 32px 0 24px;
  padding: 0 16px;
}
.banner {
  display: inline-block;
  text-align: left;
  color: var(--neon);
  font-size: 11px;
  line-height: 1.15;
  padding: 18px 28px;
  margin: 0;
  text-shadow: 0 0 10px var(--neon-soft);
  white-space: pre;
  background: rgba(0, 255, 65, 0.025);
  border: 1px solid rgba(0, 255, 65, 0.2);
  border-radius: 2px;
  box-shadow: inset 0 0 30px rgba(0, 255, 65, 0.04), 0 0 18px rgba(0, 255, 65, 0.05);
}
.banner.skull { color: var(--red); text-shadow: 0 0 8px rgba(255, 33, 71, 0.6); margin: 16px auto; }

/* Status badge (replaces ASCII skull/shield) — predictable cross-browser rendering */
.status-badge {
  text-align: center;
  margin: 32px auto;
  padding: 20px 16px;
  max-width: 560px;
  border: 1px solid;
  background: var(--bg-2);
  position: relative;
}
.status-emoji {
  font-size: 5.5em;
  line-height: 1;
  margin-bottom: 12px;
  filter: drop-shadow(0 0 18px currentColor);
  animation: pulse 2.4s ease-in-out infinite;
}
.status-frame { font-size: 12px; line-height: 1.6; letter-spacing: 0.06em; }
.status-line { color: currentColor; opacity: 0.5; white-space: nowrap; overflow: hidden; }
.status-caption { font-size: 1.5em; font-weight: 900; letter-spacing: 0.18em; margin: 4px 0; }
.status-sub { font-size: 0.95em; opacity: 0.75; letter-spacing: 0.1em; margin: 4px 0; }

.status-badge.badge-critical {
  color: var(--red);
  border-color: var(--red);
  box-shadow: 0 0 24px rgba(255, 33, 71, 0.18), inset 0 0 24px rgba(255, 33, 71, 0.08);
  background: linear-gradient(180deg, rgba(255, 33, 71, 0.04), transparent);
}
.status-badge.badge-critical .status-caption { animation: glitch 1.6s infinite; }
.status-badge.badge-danger   { color: var(--orange); border-color: var(--orange); box-shadow: 0 0 20px rgba(255, 140, 0, 0.18), inset 0 0 20px rgba(255, 140, 0, 0.06); }
.status-badge.badge-warning  { color: var(--amber);  border-color: var(--amber);  box-shadow: 0 0 20px rgba(255, 183, 0, 0.18), inset 0 0 20px rgba(255, 183, 0, 0.06); }
.status-badge.badge-ok       { color: var(--neon);   border-color: var(--neon);   box-shadow: 0 0 24px rgba(0, 255, 65, 0.22), inset 0 0 24px rgba(0, 255, 65, 0.08); background: linear-gradient(180deg, rgba(0, 255, 65, 0.04), transparent); }

@keyframes pulse {
  0%, 100% { transform: scale(1); opacity: 1; }
  50%      { transform: scale(1.05); opacity: 0.92; }
}
.title-bar {
  display: flex; justify-content: space-between; align-items: baseline;
  border-top: 1px dashed var(--neon-soft);
  border-bottom: 1px dashed var(--neon-soft);
  padding: 10px 0; margin: 24px 0;
  color: var(--neon);
}
.title-bar .left { letter-spacing: 0.2em; }
.title-bar .right { color: var(--grey); font-size: 12px; }
h1, h2, h3 { font-weight: 700; letter-spacing: 0.05em; }
h1 { color: var(--neon); margin: 0; }
h2 {
  color: var(--cyan);
  border-left: 4px solid var(--cyan);
  padding-left: 12px;
  margin: 36px 0 16px;
  text-transform: uppercase;
}
h3 { color: var(--text); margin: 20px 0 8px; }
.hr-glow { border: none; height: 1px; background: linear-gradient(90deg, transparent, var(--neon), transparent); margin: 24px 0; }

/* Score gauge */
.score-panel {
  display: grid;
  grid-template-columns: 1fr 2fr;
  gap: 24px;
  background: var(--bg-2);
  border: 1px solid var(--neon-soft);
  padding: 24px;
  margin: 24px 0;
  position: relative;
  overflow: hidden;
}
.score-panel::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(circle at 80% 50%, rgba(0,255,65,0.06), transparent 60%);
  pointer-events: none;
}
.score-display { text-align: center; }
.score-num {
  font-size: 6.5em; line-height: 1; font-weight: 900;
  text-shadow: 0 0 20px currentColor;
  margin-bottom: 4px;
}
.score-num small { font-size: 0.3em; color: var(--grey); text-shadow: none; }
.grade-letter {
  font-size: 2.2em; font-weight: 900; letter-spacing: 0.15em;
  margin-top: 8px;
}
.grade-label {
  font-size: 0.95em; color: var(--text); letter-spacing: 0.25em;
  text-transform: uppercase; margin-top: 4px;
}
.grade-a { color: var(--neon); text-shadow: 0 0 12px var(--neon-soft); }
.grade-b { color: #88ff00; text-shadow: 0 0 12px rgba(136, 255, 0, 0.5); }
.grade-c { color: var(--amber); text-shadow: 0 0 12px rgba(255, 183, 0, 0.5); }
.grade-d { color: var(--orange); text-shadow: 0 0 12px rgba(255, 140, 0, 0.5); }
.grade-f { color: var(--red); text-shadow: 0 0 16px rgba(255, 33, 71, 0.6); animation: glitch 1.6s infinite; }
@keyframes glitch {
  0%, 100% { transform: translate(0,0); }
  20%      { transform: translate(-1px, 1px); }
  40%      { transform: translate(1px, -1px); }
  60%      { transform: translate(-1px, 0); }
  80%      { transform: translate(1px, 1px); }
}
.score-bar {
  height: 8px; background: var(--bg-3); border-radius: 4px;
  margin: 16px 0; overflow: hidden; position: relative;
}
.score-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--red), var(--orange), var(--amber), #88ff00, var(--neon));
  background-size: 100% 100%;
  position: relative;
}
.score-meta { display: flex; flex-direction: column; gap: 12px; }
.diagnosis {
  font-size: 1.05em;
  color: var(--text);
  border-left: 3px solid var(--cyan);
  padding-left: 12px;
}
.diagnosis::before { content: '> '; color: var(--cyan); font-weight: 700; }

/* Severity counts strip */
.sev-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  margin: 16px 0;
}
.sev-cell {
  background: var(--bg-2);
  border: 1px solid var(--bg-3);
  padding: 14px 12px;
  text-align: center;
  position: relative;
}
.sev-cell .num { font-size: 2em; font-weight: 900; }
.sev-cell .lbl { font-size: 0.75em; letter-spacing: 0.15em; text-transform: uppercase; color: var(--grey); margin-top: 4px; }
.sev-cell.crit { border-color: var(--red); }
.sev-cell.crit .num { color: var(--red); text-shadow: 0 0 10px rgba(255,33,71,0.5); }
.sev-cell.high { border-color: var(--orange); }
.sev-cell.high .num { color: var(--orange); }
.sev-cell.med  { border-color: var(--amber); }
.sev-cell.med  .num { color: var(--amber); }
.sev-cell.low  { border-color: #88ff00; }
.sev-cell.low  .num { color: #88ff00; }
.sev-cell.info { border-color: var(--cyan); }
.sev-cell.info .num { color: var(--cyan); }

/* Tables */
table {
  width: 100%; border-collapse: collapse; margin: 12px 0;
  background: var(--bg-2); border: 1px solid var(--bg-3);
  font-size: 13px;
}
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px dashed var(--bg-3); vertical-align: top; }
th { color: var(--cyan); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px; background: var(--bg-3); }
tr:hover { background: rgba(0, 255, 65, 0.03); }
.count { color: var(--neon); font-weight: 700; text-align: right; }
.muted { color: var(--grey); font-size: 0.92em; }
code, .fp { font-family: inherit; color: var(--amber); background: rgba(255, 183, 0, 0.06); padding: 1px 6px; border-radius: 2px; }

/* Severity badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 2px; font-weight: 700; font-size: 0.85em; letter-spacing: 0.05em; }
.badge.sev-critical, .badge.sev-crit { background: var(--red); color: #fff; }
.badge.sev-high { background: var(--orange); color: #1a1a1a; }
.badge.sev-medium, .badge.sev-med { background: var(--amber); color: #1a1a1a; }
.badge.sev-low { background: #88ff00; color: #1a1a1a; }
.badge.sev-info { background: var(--cyan); color: #1a1a1a; }

/* Findings (collapsible) */
.finding {
  background: var(--bg-2);
  border-left: 3px solid var(--grey);
  padding: 12px 16px;
  margin: 8px 0;
  cursor: pointer;
}
.finding[open] { background: var(--bg-3); }
.finding summary { font-weight: 600; outline: none; user-select: none; list-style: none; }
.finding summary::before { content: '▶ '; color: var(--neon); font-size: 0.8em; transition: transform 0.2s; display: inline-block; margin-right: 4px; }
.finding[open] summary::before { content: '▼ '; }
.finding.sev-critical { border-left-color: var(--red); }
.finding.sev-critical summary { color: var(--red); }
.finding.sev-high     { border-left-color: var(--orange); }
.finding.sev-high     summary { color: var(--orange); }
.finding.sev-medium   { border-left-color: var(--amber); }
.finding.sev-low      { border-left-color: #88ff00; }
.finding.sev-info     { border-left-color: var(--cyan); }
.bug-id { font-size: 0.75em; color: var(--grey); margin-right: 8px; letter-spacing: 0.05em; }

.finding-body { padding-top: 12px; padding-left: 16px; border-left: 1px dashed var(--bg-3); margin-top: 8px; }
.block { margin: 8px 0; }
.block .lbl { display: inline-block; color: var(--cyan); font-size: 0.75em; letter-spacing: 0.2em; padding: 1px 6px; background: rgba(0,240,255,0.06); border-radius: 2px; margin-right: 6px; }
.block.fix .lbl { color: var(--neon); background: rgba(0,255,65,0.06); }
.block.incident .lbl { color: var(--orange); background: rgba(255, 140, 0, 0.06); }
.block pre {
  margin: 6px 0 0; white-space: pre-wrap; word-break: break-word;
  background: var(--bg);
  padding: 10px 12px; border: 1px dashed var(--bg-3); border-radius: 2px;
  color: var(--text); font-size: 13px;
}

/* Per-source secret blocks */
details.src-block {
  background: var(--bg-2);
  border: 1px dashed var(--bg-3);
  padding: 8px 14px;
  margin: 6px 0;
}
details.src-block summary { color: var(--cyan); font-weight: 600; cursor: pointer; outline: none; list-style: none; }
details.src-block summary .src-arrow { display: inline-block; transition: transform 0.2s; color: var(--neon); margin-right: 4px; }
details.src-block[open] summary .src-arrow { transform: rotate(90deg); }
table.secrets-table { margin-top: 10px; }
table.secrets-table .fp { font-size: 0.95em; }

/* Cursor blink */
.cursor-blink { display: inline-block; width: 9px; height: 16px; background: var(--neon); animation: blink 1s step-end infinite; vertical-align: text-bottom; margin-left: 2px; }
@keyframes blink { 50% { opacity: 0; } }

footer { margin-top: 48px; padding-top: 16px; border-top: 1px dashed var(--neon-soft); color: var(--grey); font-size: 12px; text-align: center; line-height: 1.7; }
footer code { color: var(--neon); background: rgba(0,255,65,0.05); }

a { color: var(--cyan); }
a:hover { color: var(--neon); }

@media (max-width: 720px) {
  .score-panel { grid-template-columns: 1fr; }
  .sev-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<body>
<div class="wrapper">
<div class="banner-wrap"><pre class="banner">╔═══════════════════════════════════════════════════════════════════╗
║   ▄▀█ █   ▄▀█ █▀▀ █▀▀ █▄ █ ▀█▀     ▄▀█ █ █ █▀▄ █ ▀█▀              ║
║   █▀█ █   █▀█ █▄█ ██▄ █ ▀█  █      █▀█ █▄█ █▄▀ █  █               ║
║                                                                   ║
║   &gt;&gt; LOCAL EXPOSURE SURFACE — v2 — 15 MODULES — READ-ONLY &lt;&lt;      ║
╚═══════════════════════════════════════════════════════════════════╝</pre></div>

<div class="title-bar">
  <span class="left">// HOST: ${hostname_v}</span>
  <span class="right">${generated}<span class="cursor-blink"></span></span>
</div>

<section class="score-panel">
  <div class="score-display">
    <div class="score-num ${grade_class}">${score}<small>/100</small></div>
    <div class="score-bar"><div class="score-bar-fill" style="width: ${score}%;"></div></div>
    <div class="grade-letter ${grade_class}">[ ${grade_letter} ]</div>
    <div class="grade-label ${grade_class}">${grade_label}</div>
  </div>
  <div class="score-meta">
    <div class="diagnosis">${diagnosis}</div>
    <div class="muted" style="font-size: 0.92em;">
      Score = 100 − 5×CRITICAL − 2.5×HIGH − 0.3×MEDIUM − 0.05×LOW − (distinct&nbsp;secrets&nbsp;÷&nbsp;15, capped&nbsp;at&nbsp;15) − 10 if compound supply-chain risk (MCP unpinned + npm/gh publish creds).
      <br>Floor at 0. Lower = bigger blast radius if a malicious dependency lands on this machine today.
    </div>
  </div>
</section>

<section class="sev-grid">
  <div class="sev-cell crit"><div class="num">${crit}</div><div class="lbl">Critical</div></div>
  <div class="sev-cell high"><div class="num">${high}</div><div class="lbl">High</div></div>
  <div class="sev-cell med"><div class="num">${med}</div><div class="lbl">Medium</div></div>
  <div class="sev-cell low"><div class="num">${low}</div><div class="lbl">Low</div></div>
  <div class="sev-cell info"><div class="num">${info}</div><div class="lbl">Info</div></div>
</section>

HTML_HEAD

  # Status badge — big emoji + framed caption. Renders predictably across browsers
  # (no fragile monospace ASCII art that breaks at the wrong line width).
  if (( score < 30 )); then
    cat >> "$out" <<'HTML_BADGE'
<div class="status-badge badge-critical">
  <div class="status-emoji">☠</div>
  <div class="status-frame">
    <div class="status-line">▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓</div>
    <div class="status-caption">// CRITICAL EXPOSURE DETECTED //</div>
    <div class="status-sub">SYSTEM COMPROMISED — ROTATE EVERYTHING</div>
    <div class="status-line">▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓</div>
  </div>
</div>
HTML_BADGE
  elif (( score < 50 )); then
    cat >> "$out" <<'HTML_BADGE'
<div class="status-badge badge-danger">
  <div class="status-emoji">⚠</div>
  <div class="status-frame">
    <div class="status-line">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>
    <div class="status-caption">// HIGH EXPOSURE //</div>
    <div class="status-sub">Multiple incident-class vectors pre-loaded</div>
    <div class="status-line">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</div>
  </div>
</div>
HTML_BADGE
  elif (( score < 70 )); then
    cat >> "$out" <<'HTML_BADGE'
<div class="status-badge badge-warning">
  <div class="status-emoji">◆</div>
  <div class="status-frame">
    <div class="status-line">─────────────────────────────────────</div>
    <div class="status-caption">// HARDENING NEEDED //</div>
    <div class="status-sub">Hygiene work pending — no incident-class exposure</div>
    <div class="status-line">─────────────────────────────────────</div>
  </div>
</div>
HTML_BADGE
  else
    cat >> "$out" <<'HTML_BADGE'
<div class="status-badge badge-ok">
  <div class="status-emoji">✓</div>
  <div class="status-frame">
    <div class="status-line">═════════════════════════════════════</div>
    <div class="status-caption">// SYSTEM STABLE //</div>
    <div class="status-sub">Maintain hygiene — re-run weekly to detect drift</div>
    <div class="status-line">═════════════════════════════════════</div>
  </div>
</div>
HTML_BADGE
  fi

  # ---------- Section: Keys to rotate ----------
  if [[ -f "$SECRETS_INVENTORY" ]] && (( secrets > 0 )); then
    {
      echo
      echo '<h2>🔑 Keys detected in history / sessions</h2>'
      echo "<p class=\"muted\">${secrets} distinct classified credentials found across history files and AI session storage. <strong>No raw values are stored anywhere</strong> — only redacted fingerprints (first 4 + last 4 chars + length) sufficient to identify each key in the provider UI when rotating. The audit does <strong>not</strong> verify whether any of these are still active — treat them all as live and rotate.</p>"
      echo
      echo '<h3>Summary by service</h3>'
      echo '<table>'
      echo '<thead><tr><th>Count</th><th>Service / Type</th><th>Severity hint</th><th>Where to rotate</th></tr></thead>'
      echo '<tbody>'
      _html_secrets_summary_rows
      echo '</tbody></table>'
      echo
      echo '<h3>Per-source breakdown</h3>'
      echo '<p class="muted">Each row = one distinct secret with its redacted fingerprint. Same type appearing N times means N different keys — each needs its own rotation.</p>'
      _html_secrets_per_source
    } >> "$out"
  fi

  # ---------- Section: CRITICAL ----------
  if (( crit > 0 )); then
    {
      echo
      echo "<h2>🩸 Critical bugs &mdash; today (${crit})</h2>"
      echo '<p class="muted">These directly enable a documented incident class — Nx s1ngularity-style credential exfil, PocketOS-style production deletion, MCP RCE, etc. Fix today.</p>'
      _html_render_findings_for_sev "CRITICAL" "sev-critical"
    } >> "$out"
  fi

  # ---------- Section: HIGH ----------
  if (( high > 0 )); then
    {
      echo
      echo "<h2>🟠 High &mdash; this week (${high})</h2>"
      echo '<p class="muted">Significantly amplify blast radius if anything goes wrong. Fix within seven days.</p>'
      _html_render_findings_for_sev "HIGH" "sev-high"
    } >> "$out"
  fi

  # ---------- Section: MEDIUM ----------
  if (( med > 0 )); then
    {
      echo
      echo "<h2>🟡 Medium &mdash; this month (${med})</h2>"
      echo '<p class="muted">Hygiene issues. Walk through these once a month.</p>'
      _html_render_findings_for_sev "MEDIUM" "sev-medium"
    } >> "$out"
  fi

  # ---------- Section: LOW + INFO (collapsed by default) ----------
  if (( low > 0 || info > 0 )); then
    {
      echo
      echo "<h2>🟢 Low &amp; ℹ️ Info ($((low+info)))</h2>"
      echo '<p class="muted">Best-practice deviations and contextual data. No urgent action.</p>'
      _html_render_findings_for_sev "LOW" "sev-low"
      _html_render_findings_for_sev "INFO" "sev-info"
    } >> "$out"
  fi

  # ---------- Footer ----------
  cat >> "$out" <<HTML_FOOT

<hr class="hr-glow">

<footer>
  <div>// Audit complete &mdash; ${total} findings across 15 modules. Re-run weekly:</div>
  <div><code>bash scripts/run-audit.sh</code></div>
  <div style="margin-top: 12px;">Reports: <code>audit-report.md</code> &middot; <code>audit-report.json</code> &middot; <code>secrets-inventory.md</code> &middot; <code>action-plan.md</code> &middot; <code>audit-report.html</code></div>
  <div style="margin-top: 12px; opacity: 0.65;">// generated by ai-agent-audit &mdash; read-only, no network, fingerprint-only secret display</div>
</footer>

</div>
</body>
</html>
HTML_FOOT
}

export -f compute_security_score compute_grade compute_grade_class \
          html_escape generate_html_report \
          _html_render_finding _html_render_findings_for_sev \
          _html_secrets_summary_rows _html_secrets_per_source _html_diagnosis
