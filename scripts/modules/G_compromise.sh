#!/usr/bin/env bash
# Module G: Detection of Nx-style supply chain compromise indicators
# Based on s1ngularity attack (August 2025, ongoing variants)
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="G"
log "$MODULE" "Starting Nx-style compromise detection..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# Compromised Nx versions (formerly G.1) are detected by module N, which keeps the single
# IOC list and checks declared, locked and installed versions.

# ---------- G.2: Shell init injection (post-Nx shutdown trick) ----------
SHELL_RC_FILES=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshenv")
SHUTDOWN_RE='(^|[;&|[:space:]])(sudo[[:space:]]+)?(shutdown[[:space:]]+-[hP]|halt([[:space:]]|;|$)|poweroff([[:space:]]|;|$))'
for rc in "${SHELL_RC_FILES[@]}"; do
  [[ -f "$rc" ]] || continue
  # Anchored to a command position, and comment lines are skipped: "# halt on error"
  # must not read as the s1ngularity payload.
  line=$(grep -nE "$SHUTDOWN_RE" "$rc" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -1)
  if [[ -n "$line" ]]; then
    emit_finding "$MODULE" "CRITICAL" "G.2.shutdown" \
      "Shutdown command in shell init file: $rc" \
      "Line: $line. This is the s1ngularity 'environmental sabotage' payload — terminal will crash on every new session." \
      "Remove the line immediately. Treat the system as compromised: rotate all credentials, audit recent activity." \
      "Nx s1ngularity destructive payload"
  fi
done

# ---------- G.3 / G.8: exfiltration repos on the GitHub account ----------
# gh repo list returns 30 repos by default; ask for all of them.
gh_repos=""
if [[ "$HAS_GH" -eq 1 ]] && gh auth status >/dev/null 2>&1; then
  gh_repos=$(gh repo list -L 1000 --json name,description \
    --jq '.[] | [.name, (.description // "")] | @tsv' 2>/dev/null || true)
fi
if [[ -n "$gh_repos" ]]; then
  if printf '%s\n' "$gh_repos" | cut -f1 | grep -qiE 's1ngularity-repository'; then
    emit_finding "$MODULE" "CRITICAL" "G.3.repo" \
      "GitHub account has s1ngularity-repository* on it" \
      "This repo is the exfiltration target of the Nx s1ngularity attack." \
      "URGENT: (1) Make all such repos private/delete, (2) check repo content for what was leaked (results.b64), (3) rotate every credential found, (4) review GitHub audit log for suspicious actions during attack window." \
      "Nx s1ngularity attack signature"
  fi
  # Shai-Hulud npm worms (Sept 2025: repos named "Shai-Hulud"; Nov 2025 "Second Coming":
  # description "Sha1-Hulud: The Second Coming."). Indicators as published in late 2025.
  hulud=$(printf '%s\n' "$gh_repos" | grep -iE 'shai-?hulud|sha1-hulud' | cut -f1 | head -3 | tr '\n' ' ')
  if [[ -n "$hulud" ]]; then
    emit_finding "$MODULE" "CRITICAL" "G.8.repo" \
      "GitHub account has Shai-Hulud exfiltration repo(s): $hulud" \
      "Shai-Hulud worms publish harvested credentials to a repo on the victim's own account." \
      "URGENT: make the repo private or delete it after saving evidence, rotate every credential (GitHub, npm, cloud, AI keys), review npm packages you maintain for unexpected new versions, check GitHub audit log." \
      "Shai-Hulud npm worm (Sept 2025) and Sha1-Hulud: The Second Coming (Nov 2025)"
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
POSTINSTALL_CAP=2000
suspicious_postinstall=0
scanned_pj=0
for p in "${ENV_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r pj; do
    [[ -z "$pj" ]] && continue
    scanned_pj=$((scanned_pj+1))
    # look for postinstall referring to suspicious patterns
    if grep -qE '"(pre|post)?install"[[:space:]]*:[^,}]*(curl|wget|base64|node[[:space:]]+-e|eval|telemetry\.js|setup_bun\.js|bun_environment\.js)' "$pj" 2>/dev/null; then
      suspicious_postinstall=$((suspicious_postinstall+1))
      [[ $suspicious_postinstall -le 5 ]] && \
        emit_finding "$MODULE" "HIGH" "G.6.postinstall" \
          "Suspicious postinstall script: $pj" \
          "An install script running curl/wget/base64/eval, or the known payload names telemetry.js / setup_bun.js / bun_environment.js, is a supply-chain attack pattern." \
          "Inspect package.json. Run with --ignore-scripts: npm install --ignore-scripts. Audit dependencies with npm audit and snyk test." \
          "Nx s1ngularity used postinstall (telemetry.js)"
    fi
  done < <(find "$p" -maxdepth 5 -path '*/node_modules/*/package.json' 2>/dev/null | head -"$POSTINSTALL_CAP")
  if [[ "$scanned_pj" -ge "$POSTINSTALL_CAP" ]]; then
    emit_finding "$MODULE" "INFO" "G.6.capped" \
      "Install-script scan stopped at $POSTINSTALL_CAP package.json files under $p" \
      "Packages beyond the cap were not checked for malicious install scripts." "" ""
  fi
  scanned_pj=0
done

# ---------- G.8 (local): Shai-Hulud payload files in node_modules ----------
for p in "${ENV_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  hit=$(find "$p" -maxdepth 6 -path '*/node_modules/*' \( -name 'setup_bun.js' -o -name 'bun_environment.js' \) 2>/dev/null | head -3)
  if [[ -n "$hit" ]]; then
    emit_finding "$MODULE" "CRITICAL" "G.8.local" \
      "Shai-Hulud payload file(s) in node_modules under $p" \
      "Paths:"$'\n'"$hit" \
      "Treat the machine as compromised: rotate all credentials, remove the affected node_modules, find which dependency shipped the file (npm ls) and pin a clean version." \
      "Sha1-Hulud: The Second Coming (Nov 2025) — preinstall ran setup_bun.js / bun_environment.js"
  fi
done

# ---------- G.7: Telemetry.js artifact specifically ----------
if find "$HOME" -maxdepth 6 -name 'telemetry.js' -path '*/node_modules/nx/*' 2>/dev/null | grep -q .; then
  emit_finding "$MODULE" "MEDIUM" "G.7.telemetry" \
    "telemetry.js found inside node_modules/nx" \
    "Even legitimate Nx versions ship a telemetry.js. Compare hash to known-good." \
    "If you suspect compromise: clean install: rm -rf node_modules && npm install" ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
