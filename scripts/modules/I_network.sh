#!/usr/bin/env bash
# Module I: Network egress controls
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="I"
log "$MODULE" "Starting network egress audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# Firewall presence
if [[ "$OS" == "macos" ]]; then
  if has /usr/libexec/ApplicationFirewall/socketfilterfw; then
    state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
    if echo "$state" | grep -qi 'enabled'; then
      emit_finding "$MODULE" "INFO" "I.fw" "macOS Application Firewall enabled" "Note: this filters incoming, not outgoing." "" ""
    else
      emit_finding "$MODULE" "LOW" "I.fw" "macOS Application Firewall disabled" "" "Settings → Network → Firewall → Turn On" ""
    fi
  fi
  # Little Snitch / LuLu detection
  if [[ -d "/Applications/Little Snitch.app" || -d "/Applications/LuLu.app" ]]; then
    emit_finding "$MODULE" "INFO" "I.egress" "Outbound firewall present (Little Snitch / LuLu)" "Good — can block unexpected egress." "" ""
  else
    emit_finding "$MODULE" "MEDIUM" "I.noegress" \
      "No outbound firewall (Little Snitch / LuLu) detected on macOS" \
      "AI agents can POST credentials to any endpoint without notice." \
      "Install Little Snitch or LuLu (free, open-source). Set rules per-app." \
      "CVE-2025-55284 — Claude Code DNS exfiltration bypassed network monitoring"
  fi
elif [[ "$OS" == "linux" ]]; then
  if has ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
    emit_finding "$MODULE" "INFO" "I.fw" "ufw active" "" "" ""
  elif has firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then
    emit_finding "$MODULE" "INFO" "I.fw" "firewalld running" "" "" ""
  else
    emit_finding "$MODULE" "LOW" "I.nofw" "No firewall detected (ufw/firewalld)" "" "Enable: sudo ufw enable" ""
  fi
fi

# HTTP_PROXY env vars
if [[ -n "${HTTP_PROXY:-}" || -n "${HTTPS_PROXY:-}" || -n "${http_proxy:-}" || -n "${https_proxy:-}" ]]; then
  emit_finding "$MODULE" "INFO" "I.proxy" "HTTP(S) proxy configured" "Egress can be inspected. Good for monitoring AI agent calls." "" ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
