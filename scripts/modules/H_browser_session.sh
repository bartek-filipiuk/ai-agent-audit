#!/usr/bin/env bash
# Module H: Browser / session hygiene (heuristic — minimal intrusion)
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="H"
log "$MODULE" "Starting browser/session hygiene audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# Detect browser profiles (existence, not content)
declare -A BROWSERS_MAC=(
  ["Chrome"]="$HOME/Library/Application Support/Google/Chrome"
  ["Edge"]="$HOME/Library/Application Support/Microsoft Edge"
  ["Brave"]="$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
  ["Firefox"]="$HOME/Library/Application Support/Firefox"
  ["Arc"]="$HOME/Library/Application Support/Arc"
)
declare -A BROWSERS_LINUX=(
  ["Chrome"]="$HOME/.config/google-chrome"
  ["Chromium"]="$HOME/.config/chromium"
  ["Brave"]="$HOME/.config/BraveSoftware/Brave-Browser"
  ["Firefox"]="$HOME/.mozilla/firefox"
)

if [[ "$OS" == "macos" ]]; then
  for name in "${!BROWSERS_MAC[@]}"; do
    if [[ -d "${BROWSERS_MAC[$name]}" ]]; then
      emit_finding "$MODULE" "INFO" "H.browser" "$name browser data present" "Active browser sessions accessible by any process running as this user." "" ""
    fi
  done
else
  for name in "${!BROWSERS_LINUX[@]}"; do
    if [[ -d "${BROWSERS_LINUX[$name]}" ]]; then
      emit_finding "$MODULE" "INFO" "H.browser" "$name browser data present" "" "" ""
    fi
  done
fi

# 1Password CLI
if has op; then
  if op whoami >/dev/null 2>&1; then
    emit_finding "$MODULE" "MEDIUM" "H.1p" \
      "1Password CLI is currently signed in" \
      "Any process running as this user can call 'op item get …' and retrieve secrets without a prompt." \
      "Sign out when not actively using: op signout. Better: use biometric prompt per-call (settings → CLI integration)." \
      ""
  fi
fi

# Bitwarden CLI
if has bw; then
  if bw status 2>/dev/null | grep -q '"unlocked"'; then
    emit_finding "$MODULE" "MEDIUM" "H.bw" \
      "Bitwarden vault is currently unlocked" \
      "Same risk as 1Password unlocked." \
      "bw lock when not actively using." ""
  fi
fi

# pass — password store
[[ -d "$HOME/.password-store" ]] && \
  emit_finding "$MODULE" "INFO" "H.pass" "pass (password-store) directory exists" "GPG-backed; safety depends on GPG agent state." "" ""

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
