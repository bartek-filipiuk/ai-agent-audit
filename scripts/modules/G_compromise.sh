#!/usr/bin/env bash
# Module G: Detection of Nx-style supply chain compromise indicators
# Based on s1ngularity attack (August 2025, ongoing variants)
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="G"
log "$MODULE" "Starting Nx-style compromise detection..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# ---------- G.1: Vulnerable Nx versions ----------
nx_findings=0
while IFS=$'\t' read -r pj ver; do
  [[ -z "$pj" ]] && continue
  if is_nx_compromised_version "$ver"; then
    nx_findings=$((nx_findings+1))
    emit_finding "$MODULE" "CRITICAL" "G.1.nxversion" \
      "Compromised Nx version detected: $ver in $pj" \
      "This version was published with malware (s1ngularity attack, August 2025). Range 20.9.0–20.12.0 and 21.5.0–21.8.0 are confirmed compromised." \
      "Immediately: (1) rotate ALL credentials this machine had access to (GitHub, npm, AWS, SSH, crypto), (2) reinstall a safe Nx version, (3) check for s1ngularity-repository on your GitHub account, (4) inspect ~/.bashrc and ~/.zshrc for shutdown injection. Full guide: https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c" \
      "Nx s1ngularity attack (Aug 2025) — 1079 systems compromised, 2349 credentials harvested"
  fi
done < <(find_nx_versions)

if [[ "$nx_findings" -eq 0 ]]; then
  emit_finding "$MODULE" "INFO" "G.1.nxsafe" "No compromised Nx versions detected in scanned project paths" "" "" ""
fi

# ---------- G.2: Shell init injection (post-Nx shutdown trick) ----------
SHELL_RC_FILES=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshenv")
for rc in "${SHELL_RC_FILES[@]}"; do
  [[ -f "$rc" ]] || continue
  if grep -qE 'sudo\s+shutdown\s+-h\s+0|shutdown\s+-h\s+now|halt' "$rc" 2>/dev/null; then
    line=$(grep -nE 'sudo\s+shutdown|shutdown\s+-h\s+now|halt' "$rc" | head -1)
    emit_finding "$MODULE" "CRITICAL" "G.2.shutdown" \
      "Shutdown command in shell init file: $rc" \
      "Line: $line. This is the s1ngularity 'environmental sabotage' payload — terminal will crash on every new session." \
      "Remove the line immediately. Treat the system as compromised: rotate all credentials, audit recent activity." \
      "Nx s1ngularity destructive payload"
  fi
done

# ---------- G.3: s1ngularity-repository on local GitHub ----------
if [[ "$HAS_GH" -eq 1 ]] && gh auth status >/dev/null 2>&1; then
  if gh repo list --json name --jq '.[].name' 2>/dev/null | grep -qiE 's1ngularity-repository'; then
    emit_finding "$MODULE" "CRITICAL" "G.3.repo" \
      "GitHub account has s1ngularity-repository* on it" \
      "This repo is the exfiltration target of the Nx s1ngularity attack." \
      "URGENT: (1) Make all such repos private/delete, (2) check repo content for what was leaked (results.b64), (3) rotate every credential found, (4) review GitHub audit log for suspicious actions during attack window." \
      "Nx s1ngularity attack signature"
  fi
fi

# ---------- G.4: /tmp/inventory.txt ----------
if [[ -f /tmp/inventory.txt ]]; then
  emit_finding "$MODULE" "CRITICAL" "G.4.inventory" \
    "/tmp/inventory.txt exists" \
    "This is the staging file used by Nx s1ngularity malware to build the exfiltration payload." \
    "Treat machine as compromised. Inspect file content (cat /tmp/inventory.txt | head). Rotate credentials. Investigate when it was created." \
    "Nx s1ngularity malware artifact"
fi

# ---------- G.5: Recent shell init modifications ----------
# Compare modification times — anything modified recently that wasn't expected
for rc in "${SHELL_RC_FILES[@]}"; do
  [[ -f "$rc" ]] || continue
  if [[ "$OS" == "macos" ]]; then
    mtime=$(stat -f '%m' "$rc" 2>/dev/null)
  else
    mtime=$(stat -c '%Y' "$rc" 2>/dev/null)
  fi
  now=$(date +%s)
  age_days=$(( (now - mtime) / 86400 ))
  if [[ "$age_days" -lt 30 ]]; then
    emit_finding "$MODULE" "INFO" "G.5.recent" \
      "$rc modified $age_days day(s) ago" \
      "If you didn't make this change, investigate. Compare to git history if rc files are in dotfiles repo." \
      "Diff against backup: diff $rc \$BACKUP/$rc" ""
  fi
done

# ---------- G.6: Suspicious npm postinstall scripts in current node_modules ----------
ENV_PATHS=("$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work")
suspicious_postinstall=0
for p in "${ENV_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r pj; do
    [[ -z "$pj" ]] && continue
    # look for postinstall referring to suspicious patterns
    if grep -qE '"postinstall".*(curl|wget|base64|node\s+-e|eval)' "$pj" 2>/dev/null; then
      suspicious_postinstall=$((suspicious_postinstall+1))
      [[ $suspicious_postinstall -le 5 ]] && \
        emit_finding "$MODULE" "HIGH" "G.6.postinstall" \
          "Suspicious postinstall script: $pj" \
          "Postinstall containing curl/wget/base64/eval is a known supply chain attack pattern." \
          "Inspect package.json. Run with --ignore-scripts: npm install --ignore-scripts. Audit dependencies with npm audit and snyk test." \
          "Nx s1ngularity used postinstall (telemetry.js)"
    fi
  done < <(find "$p" -maxdepth 5 -path '*/node_modules/*/package.json' 2>/dev/null | head -200)
done

# ---------- G.7: Telemetry.js artifact specifically ----------
if find "$HOME" -maxdepth 6 -name 'telemetry.js' -path '*/node_modules/nx/*' 2>/dev/null | grep -q .; then
  emit_finding "$MODULE" "MEDIUM" "G.7.telemetry" \
    "telemetry.js found inside node_modules/nx" \
    "Even legitimate Nx versions ship a telemetry.js. Compare hash to known-good." \
    "If you suspect compromise: clean install: rm -rf node_modules && npm install" ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
