#!/usr/bin/env bash
# AI Agent Audit — main orchestrator
# Runs all modules and aggregates results into JSON + Markdown reports.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ALL_MODULES="A B C D E F G H I J K L M N P"
MODULES_TO_RUN="$ALL_MODULES"
OPEN_HTML=1
OUTPUT_DIR=""

# Arguments are parsed before common.sh is sourced: common.sh creates the output
# directory, and it must create the one the user asked for, not the default.

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --modules|--output)
      if [[ $# -lt 2 || -z "$2" ]]; then
        printf '[ERR] %s needs a value\n' "$1" >&2; exit 1
      fi
      if [[ "$1" == "--modules" ]]; then MODULES_TO_RUN="${2//,/ }"; else OUTPUT_DIR="$2"; fi
      shift 2 ;;
    --no-open) OPEN_HTML=0; shift ;;
    -h|--help)
      cat <<EOF
ai-agent-audit — local developer machine audit for AI-agent risks
Usage: $0 [--modules A,B,G] [--output ~/.ai-agent-audit] [--no-open]

Modules:
  A  Credentials (SSH, cloud, package managers, env files)
  B  AI tool configuration (CLIs, MCP, dangerous flags)
  C  Token scope (GitHub, AWS, npm)
  D  Environment separation (dev/prod profiles)
  E  Backup hygiene
  F  Sandbox / isolation (containers, groups, sudo)
  G  Nx-style compromise detection
  H  Browser / password manager session state
  I  Network egress controls
  J  Shell history + AI session credential leak detection (with secret classification)
  K  AI hooks + repo-level config files (CVE-2025-59536 / CVE-2026-21852)
  L  AI skills / plugins supply-chain (ToxicSkills, ClawHub)
  M  MCP server inventory + risk
  N  Compromised package detection (axios mar 2026, Bitwarden CLI 2026.4.0, Nx, etc.)
  P  macOS-specific (TCC, LaunchAgents, Time Machine, Spotlight, SIP) — skips on Linux

Output:
  \$AUDIT_DIR/findings/<module>.jsonl    — raw findings (JSONL)
  \$AUDIT_DIR/audit-report.json          — aggregated machine-readable (includes score + secrets summary)
  \$AUDIT_DIR/audit-report.md            — human-readable report
  \$AUDIT_DIR/audit-report.html          — cyberpunk-themed HTML report (auto-opens in browser)
  \$AUDIT_DIR/secrets-inventory.md       — classified secrets (per source, redacted fingerprints)
  \$AUDIT_DIR/action-plan.md             — prioritised checklist (start here)

By default the HTML report auto-opens via xdg-open / open at the end of the run.
Pass --no-open to skip that.
EOF
      exit 0 ;;
    *) printf '[ERR] Unknown arg: %s\n' "$1" >&2; exit 1 ;;
  esac
done

[[ -n "$OUTPUT_DIR" ]] && AUDIT_DIR="$OUTPUT_DIR"
AUDIT_DIR="${AUDIT_DIR:-$HOME/.ai-agent-audit}"
FINDINGS_DIR="$AUDIT_DIR/findings"
export AUDIT_DIR FINDINGS_DIR
source "$SCRIPT_DIR/lib/common.sh"

# Map module letter to script
declare -A MODULE_SCRIPTS=(
  [A]="A_credentials.sh"
  [B]="B_ai_tools.sh"
  [C]="C_tokens.sh"
  [D]="D_env_separation.sh"
  [E]="E_backup.sh"
  [F]="F_sandbox.sh"
  [G]="G_compromise.sh"
  [H]="H_browser_session.sh"
  [I]="I_network.sh"
  [J]="J_history_sessions.sh"
  [K]="K_hooks.sh"
  [L]="L_skills.sh"
  [M]="M_mcp.sh"
  [N]="N_packages.sh"
  [P]="P_macos.sh"
)

# Reset findings and the secrets inventory so the reports reflect this run only.
# Without this, a --modules run would aggregate stale findings from older runs.
rm -f "$FINDINGS_DIR"/*.jsonl
SECRETS_INVENTORY="${AUDIT_DIR}/secrets-inventory.md"
rm -f "$SECRETS_INVENTORY"
export SECRETS_INVENTORY

echo
echo "═══════════════════════════════════════════════════════════"
echo "  AI Agent Audit — running"
echo "  OS: $OS  |  Output: $AUDIT_DIR"
echo "  Modules: $MODULES_TO_RUN"
echo "═══════════════════════════════════════════════════════════"
echo

if [[ "$MODULES_TO_RUN" != "$ALL_MODULES" ]]; then
  echo "  Partial run: score and reports reflect only modules $MODULES_TO_RUN."
  echo
fi

# Run each requested module
MODULES_RUN=""
for m in $MODULES_TO_RUN; do
  s="${MODULE_SCRIPTS[$m]:-}"
  if [[ -z "$s" ]]; then
    warn "Unknown module: $m — skipping"
    continue
  fi
  script_path="$SCRIPT_DIR/modules/$s"
  if [[ ! -f "$script_path" ]]; then
    warn "Module script missing: $script_path"
    continue
  fi
  MODULES_RUN="${MODULES_RUN:+$MODULES_RUN }$m"
  bash "$script_path" || warn "Module $m exited with non-zero"
done
export MODULES_RUN

# Aggregate
bash "$SCRIPT_DIR/aggregate.sh"

# Files from older runs keep their old mode when truncated with '>'; tighten everything.
chmod -R go-rwx "$AUDIT_DIR" 2>/dev/null
rm -rf "$AUDIT_DIR/tmp"

echo
echo "═══════════════════════════════════════════════════════════"
echo "  Audit complete."
echo "  Reports:"
echo "    $AUDIT_DIR/audit-report.md"
echo "    $AUDIT_DIR/audit-report.json"
[[ -f "$AUDIT_DIR/audit-report.html" ]] && \
echo "    $AUDIT_DIR/audit-report.html     (cyberpunk HTML — auto-opens in browser)"
[[ -f "$AUDIT_DIR/secrets-inventory.md" ]] && \
echo "    $AUDIT_DIR/secrets-inventory.md  (classified secrets, redacted fingerprints)"
[[ -f "$AUDIT_DIR/action-plan.md" ]] && \
echo "    $AUDIT_DIR/action-plan.md        (prioritised checklist — start here)"
echo "═══════════════════════════════════════════════════════════"

# Auto-open HTML report (best-effort; silent fail if no display).
if [[ "$OPEN_HTML" -eq 1 && -f "$AUDIT_DIR/audit-report.html" ]]; then
  if [[ "$OS" == "macos" ]] && has open; then
    open "$AUDIT_DIR/audit-report.html" >/dev/null 2>&1 &
  elif [[ "$OS" == "linux" ]] && has xdg-open && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    xdg-open "$AUDIT_DIR/audit-report.html" >/dev/null 2>&1 &
  fi
fi
