#!/usr/bin/env bash
# AI Agent Audit — main orchestrator
# Runs all modules and aggregates results into JSON + Markdown reports.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

MODULES_TO_RUN="A B C D E F G H I J K L M N P"

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --modules) MODULES_TO_RUN="${2//,/ }"; shift 2 ;;
    --output)  AUDIT_DIR="$2"; FINDINGS_DIR="$AUDIT_DIR/findings"; mkdir -p "$FINDINGS_DIR"; shift 2 ;;
    -h|--help)
      cat <<EOF
ai-agent-audit — local developer machine audit for AI-agent risks
Usage: $0 [--modules A,B,G] [--output ~/.ai-agent-audit]

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
  \$AUDIT_DIR/audit-report.json          — aggregated machine-readable
  \$AUDIT_DIR/audit-report.md            — human-readable report
  \$AUDIT_DIR/secrets-inventory.md       — classified secrets (per source, redacted fingerprints)
  \$AUDIT_DIR/action-plan.md             — prioritised checklist (start here)
EOF
      exit 0 ;;
    *) err "Unknown arg: $1"; exit 1 ;;
  esac
done

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

# Reset secrets inventory at the start of each run so it reflects the current scan only.
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

# Run each requested module
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
  bash "$script_path" || warn "Module $m exited with non-zero"
done

# Aggregate
bash "$SCRIPT_DIR/aggregate.sh"

echo
echo "═══════════════════════════════════════════════════════════"
echo "  Audit complete."
echo "  Reports:"
echo "    $AUDIT_DIR/audit-report.md"
echo "    $AUDIT_DIR/audit-report.json"
[[ -f "$AUDIT_DIR/secrets-inventory.md" ]] && \
echo "    $AUDIT_DIR/secrets-inventory.md  (classified secrets, redacted fingerprints)"
[[ -f "$AUDIT_DIR/action-plan.md" ]] && \
echo "    $AUDIT_DIR/action-plan.md        (prioritised checklist — start here)"
echo "═══════════════════════════════════════════════════════════"
