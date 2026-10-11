#!/usr/bin/env bash
# Module P: macOS-specific audit
#
# Skips entirely on non-macOS hosts.
#
# Covers:
#   - TCC.db (apps with Full Disk Access / AppleEvents / Accessibility / Camera / Mic)
#   - LaunchAgents / LaunchDaemons (persistence — Sapphire Sleet, April 2026)
#   - Keychain unlock state
#   - Time Machine destination security
#   - Brewfile / unknown taps
#   - Spotlight indexing of credential dirs
#   - Gatekeeper / SIP status
#   - Quarantine state of recent downloads
#   - Codex / autonomous-agent app inventory

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="P"
log "$MODULE" "Starting macOS-specific audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

if [[ "$OS" != "macos" ]]; then
  log "$MODULE" "Skipped (not macOS)."
  emit_finding "$MODULE" "INFO" "P.skip" "macOS-specific module skipped (host OS: $OS)" "" "" ""
  exit 0
fi

# ---------- P.1: TCC.db (Full Disk Access etc.) ----------
USER_TCC="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [[ -f "$USER_TCC" && "$HAS_SQLITE" -eq 1 ]] && \
   ! sqlite3 "$USER_TCC" 'SELECT 1 FROM access LIMIT 1;' >/dev/null 2>&1; then
  emit_finding "$MODULE" "INFO" "P.1.tcc.unreadable" \
    "TCC.db is not readable — privacy permissions were not checked" \
    "Path: $USER_TCC. Reading it requires Full Disk Access for the terminal running the audit." \
    "Grant your terminal Full Disk Access (System Settings → Privacy & Security → Full Disk Access), re-run the audit, then revoke it again." \
    ""
elif [[ -f "$USER_TCC" && "$HAS_SQLITE" -eq 1 ]]; then
  # High-impact services. Since macOS 11 the column is auth_value
  # (0 denied, 1 unknown, 2 allowed, 3 limited); the old 'allowed' column is gone.
  while IFS='|' read -r client service allowed; do
    [[ -z "$client" ]] && continue
    if [[ "$allowed" == "2" || "$allowed" == "3" ]]; then
      case "$service" in
        kTCCServiceSystemPolicyAllFiles)  svc_label="Full Disk Access" ;;
        kTCCServiceAppleEvents)           svc_label="AppleEvents (can drive other apps)" ;;
        kTCCServiceAccessibility)         svc_label="Accessibility (can read/inject input)" ;;
        kTCCServiceScreenCapture)         svc_label="Screen Recording" ;;
        kTCCServiceListenEvent)           svc_label="Input Monitoring" ;;
        kTCCServiceMicrophone)            svc_label="Microphone" ;;
        kTCCServiceCamera)                svc_label="Camera" ;;
        *) continue ;;
      esac
      sev="INFO"
      [[ "$service" == "kTCCServiceSystemPolicyAllFiles" || "$service" == "kTCCServiceAppleEvents" || "$service" == "kTCCServiceAccessibility" ]] && sev="MEDIUM"
      emit_finding "$MODULE" "$sev" "P.1.tcc" \
        "TCC: $client has $svc_label" \
        "Service: $service. auth_value: $allowed (2 allowed, 3 limited)." \
        "Review in System Settings → Privacy & Security → $svc_label. Revoke if not needed. Especially for AI agents — these permissions persist across launches and any process using the app's bundle id inherits them." \
        "Sapphire Sleet macOS campaign (April 2026) manipulated TCC.db to grant AppleEvents to osascript silently"
    fi
  done < <(sqlite3 -separator '|' "$USER_TCC" \
    "SELECT client, service, auth_value FROM access WHERE auth_value IN (2,3) AND service IN (
       'kTCCServiceSystemPolicyAllFiles',
       'kTCCServiceAppleEvents',
       'kTCCServiceAccessibility',
       'kTCCServiceScreenCapture',
       'kTCCServiceListenEvent',
       'kTCCServiceMicrophone',
       'kTCCServiceCamera'
     );" 2>/dev/null)
fi

# ---------- P.2: LaunchAgents / LaunchDaemons (persistence) ----------
# Whitelist of known-safe prefixes. Anything else = INFO (worth eyeballing).
WHITELIST_PREFIXES='^(com\.apple|com\.docker|com\.adobe|com\.google|com\.microsoft|com\.1password|com\.spotify|com\.dropbox|com\.logi|homebrew\.mxcl|com\.parallels|com\.vmware|com\.jetbrains|com\.openvpn|net\.tunnelblick|com\.zoom|com\.slack|com\.atlassian|com\.figma|com\.colliderli|org\.mozilla)'

scan_launch_dir() {
  local dir="$1" sev="$2"
  [[ -d "$dir" ]] || return
  while IFS= read -r plist; do
    [[ -z "$plist" ]] && continue
    base=$(basename "$plist" .plist)
    # Apple never installs per-user agents, so com.apple.* under ~/Library/LaunchAgents is
    # the classic masquerade — the one place the vendor whitelist must not apply to it.
    if [[ "$dir" == "$HOME/"* && "$base" == com.apple.* ]]; then
      emit_finding "$MODULE" "HIGH" "P.2.masquerade" \
        "Per-user launch agent claims to be Apple: $plist" \
        "Label: $base. Apple ships no agents in ~/Library/LaunchAgents; a com.apple.* name there is a common malware disguise." \
        "Inspect it: plutil -p \"$plist\". If you did not create it: launchctl unload \"$plist\" && rm \"$plist\", then treat the machine as compromised and rotate credentials." \
        "Sapphire Sleet (April 2026) used LaunchAgents for C2 polling persistence"
      continue
    fi
    if printf '%s' "$base" | grep -qE "$WHITELIST_PREFIXES"; then
      continue
    fi
    # Read program / program arguments (best-effort)
    program=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$plist" 2>/dev/null \
              || /usr/libexec/PlistBuddy -c 'Print :Program' "$plist" 2>/dev/null \
              || echo "(unable to read)")
    emit_finding "$MODULE" "$sev" "P.2.launch" \
      "Unrecognized launch agent/daemon: $plist" \
      "Label: $base. Program: $(untrusted_text "$program" 120)" \
      "Verify this is something you installed. If unrecognized: launchctl unload \"$plist\" && rm \"$plist\". Persistence via LaunchAgents is the standard macOS post-exploit technique." \
      "Sapphire Sleet (April 2026) used LaunchAgents for C2 polling persistence"
  done < <(find "$dir" -maxdepth 1 -name '*.plist' -type f 2>/dev/null)
}

scan_launch_dir "$HOME/Library/LaunchAgents" "MEDIUM"
scan_launch_dir "/Library/LaunchAgents"      "MEDIUM"
scan_launch_dir "/Library/LaunchDaemons"     "HIGH"

# ---------- P.3: Keychain unlock state ----------
if has security; then
  # The login keychain unlock state isn't directly exposed without prompting; we infer from
  # whether the keychain is set to lock on sleep / after timeout.
  login_kc=$(security list-keychains -d user 2>/dev/null | grep -m1 'login.keychain' | tr -d ' "')
  if [[ -n "$login_kc" ]]; then
    info=$(security show-keychain-info "$login_kc" 2>&1 || true)
    if echo "$info" | grep -qi 'no-timeout'; then
      emit_finding "$MODULE" "HIGH" "P.3.keychain" \
        "Login keychain has NO auto-lock timeout" \
        "Keychain stays unlocked indefinitely after first auth. Any process running as you can read all stored secrets." \
        "Set: security set-keychain-settings -t 7200 -l ~/Library/Keychains/login.keychain-db (locks after 2h idle and on sleep). Or in Keychain Access → File → Change Settings → enable both." \
        "Sapphire Sleet exfiltrated *.keychain-db files when system was unlocked"
    elif echo "$info" | grep -qi 'lock-on-sleep'; then
      emit_finding "$MODULE" "INFO" "P.3.keychain" "Login keychain locks on sleep (good)" "" "" ""
    fi
  fi
fi

# ---------- P.4: Time Machine destination security ----------
if has tmutil; then
  dest_info=$(tmutil destinationinfo 2>/dev/null || true)
  if [[ -n "$dest_info" ]]; then
    if echo "$dest_info" | grep -q 'No destinations configured'; then
      emit_finding "$MODULE" "MEDIUM" "P.4.tm.none" \
        "Time Machine has no destinations configured" \
        "Combined with no other backup tool, this means no recovery if disk fails or system is compromised." \
        "Configure in System Settings → General → Time Machine → Add Backup Disk. Choose an external drive AND enable encryption." \
        "PocketOS — backups in same blast radius as production data"
    else
      # tmutil does not report encryption; ask diskutil about each mounted destination.
      unencrypted=""
      while IFS= read -r mount; do
        [[ -z "$mount" || ! -d "$mount" ]] && continue
        if ! diskutil info "$mount" 2>/dev/null | grep -qE '^[[:space:]]*(Encrypted|FileVault):[[:space:]]+Yes'; then
          unencrypted="${unencrypted:+$unencrypted, }$mount"
        fi
      done < <(printf '%s\n' "$dest_info" | sed -nE 's/^Mount Point[[:space:]]*:[[:space:]]*//p')
      if [[ -n "$unencrypted" ]]; then
        emit_finding "$MODULE" "HIGH" "P.4.tm.unenc" \
          "Time Machine destination is NOT encrypted: $unencrypted" \
          "Backup contains every file on disk including ~/.ssh, keychains, browser data. Unencrypted = same risk as the original drive being stolen, but with longer-term retention." \
          "Re-create the backup destination with encryption enabled. Settings → General → Time Machine → '+' → check Encrypt Backups." \
          ""
      fi
    fi
  fi
fi

# ---------- P.5: Homebrew taps + recent casks ----------
if has brew; then
  while IFS= read -r tap; do
    [[ -z "$tap" ]] && continue
    case "$tap" in
      homebrew/*) ;;
      *)
        emit_finding "$MODULE" "MEDIUM" "P.5.tap" \
          "Non-Homebrew tap: $tap" \
          "Third-party taps ship arbitrary install scripts. Each tap is a supply-chain trust decision." \
          "List formulas from this tap: brew list --full-name | grep '^$tap'. If unfamiliar: brew untap $tap. Pin only taps you've explicitly vetted." \
          "" ;;
    esac
  done < <(brew tap 2>/dev/null)
fi

# ---------- P.6: Spotlight indexing ----------
# Hidden dot-dirs (~/.ssh, ~/.aws) are not indexed, so the old per-directory mdfind probe
# never fired. What matters is whether the boot volume is indexed at all: credentials
# kept in ordinary folders (~/Documents/keys.txt) are then searchable by any app.
if has mdutil && mdutil -s / 2>/dev/null | grep -qi 'Indexing enabled'; then
  emit_finding "$MODULE" "INFO" "P.6.spotlight" \
    "Spotlight indexing is enabled on /" \
    "Credential files stored outside dot-directories are searchable through Spotlight and Core Spotlight." \
    "Keep secrets in dot-directories or a password manager. To exclude a folder: System Settings → Siri & Spotlight → Spotlight Privacy → '+'." \
    ""
fi

# ---------- P.7: Gatekeeper / SIP ----------
if has csrutil; then
  state=$(csrutil status 2>/dev/null || true)
  if echo "$state" | grep -qi 'disabled'; then
    emit_finding "$MODULE" "HIGH" "P.7.sip" \
      "System Integrity Protection (SIP) is disabled" \
      "$state — SIP off means root can modify system files, including binaries that anti-malware checks." \
      "Re-enable: boot to recovery mode (Cmd-R), open Terminal, run csrutil enable, reboot." \
      ""
  fi
fi
if has spctl; then
  gk=$(spctl --status 2>/dev/null || true)
  if echo "$gk" | grep -qi 'disabled'; then
    emit_finding "$MODULE" "MEDIUM" "P.7.gatekeeper" \
      "Gatekeeper is disabled" "" \
      "Enable: sudo spctl --master-enable. Then verify with spctl --status." \
      ""
  fi
fi

# ---------- P.8: Quarantine flag on recent downloads ----------
# A binary with the quarantine xattr was Gatekeeper-checked. One without may have been moved
# in via curl/wget/airdrop and never went through code-sign verification.
if [[ -d "$HOME/Downloads" ]]; then
  recent_no_quarantine=0
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if ! xattr -p com.apple.quarantine "$f" >/dev/null 2>&1; then
      recent_no_quarantine=$((recent_no_quarantine+1))
    fi
  # .app bundles are directories, so they need their own branch (and no descent into them).
  done < <(find "$HOME/Downloads" -maxdepth 2 \
             \( -type d -name '*.app' -mtime -30 -print -prune \) -o \
             \( -type f \( -name '*.dmg' -o -name '*.pkg' -o -perm -u+x \) -mtime -30 -print \) \
             2>/dev/null | head -50)
  if [[ "$recent_no_quarantine" -gt 0 ]]; then
    emit_finding "$MODULE" "INFO" "P.8.quarantine" \
      "$recent_no_quarantine recent executable file(s) in ~/Downloads without quarantine flag" \
      "Files without com.apple.quarantine bypassed Gatekeeper code-sign verification." \
      "Review the list: find ~/Downloads -maxdepth 2 \\( -name '*.app' -o -name '*.pkg' -o -name '*.dmg' -o -type f -perm -u+x \\) -mtime -30 -exec sh -c 'xattr -p com.apple.quarantine \"\$1\" >/dev/null 2>&1 || echo \"NO-QUARANTINE: \$1\"' _ {} \\;" \
      ""
  fi
fi

# ---------- P.9: Codex / autonomous agent apps ----------
for app_path in "/Applications/Codex.app" "/Applications/Claude.app" "/Applications/Cursor.app" "/Applications/Windsurf.app"; do
  if [[ -d "$app_path" ]]; then
    bundle=$(basename "$app_path" .app)
    emit_finding "$MODULE" "INFO" "P.9.app" \
      "$bundle.app installed" \
      "Autonomous AI agent app installed at $app_path. Check its TCC permissions in P.1 above." \
      "Review System Settings → Privacy & Security entries for this app. Consider running through Agent Safehouse (sandbox) for autonomous tasks." \
      "Codex macOS (Feb 2026) — autonomous-agent terminal app introduced new YOLO-mode risk class"
  fi
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
