#!/usr/bin/env bash
# Module M: MCP server inventory and risk audit
#
# Inventories every Model Context Protocol server configured anywhere on the machine and flags:
#   - Launch via npx / uvx (supply-chain attack surface — 9/11 MCP marketplaces poisoned in 2026)
#   - Unpinned versions
#   - Servers running as a child process with full env access
#   - Plaintext secrets in MCP config (cross-references with module B but classifies per-server)
#
# Background: April 2026 Anthropic SDK design flaw → 200k MCP servers RCE-able. GitHub MCP
# prompt-injection attack (Invariant Labs, May 2025). Tool poisoning attacks (Practical
# DevSecOps 2026).

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="M"
log "$MODULE" "Starting MCP server inventory and risk audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

MCP_CONFIGS=(
  "$HOME/.cursor/mcp.json"
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
  "$HOME/.config/Claude/claude_desktop_config.json"
  "$HOME/.config/claude/mcp.json"
  "$HOME/.claude/.mcp.json"
  "$HOME/.claude.json"
  "$HOME/.codeium/windsurf/mcp_config.json"
  "$HOME/.config/Cline/MCP/cline_mcp_settings.json"
  "$HOME/Library/Application Support/Cline/MCP/cline_mcp_settings.json"
)

# Add per-project .mcp.json found in workspace
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r f; do
    [[ -n "$f" ]] && MCP_CONFIGS+=("$f")
  done < <(find "$p" -maxdepth 5 -name '.mcp.json' -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
done

total_servers=0
total_npx=0
total_uvx=0
total_pinned=0

for cfg in "${MCP_CONFIGS[@]}"; do
  [[ -f "$cfg" ]] || continue

  emit_finding "$MODULE" "INFO" "M.1.found" "MCP config: $cfg" "" "" ""

  # Inventory each server. Two extraction paths: jq (preferred) or grep heuristic fallback.
  declare -a srv_names=()
  declare -A srv_command srv_args

  if [[ "$HAS_JQ" -eq 1 ]]; then
    # Both schemas: top-level "mcpServers" (Claude Desktop) and "servers" (some forks)
    while IFS=$'\t' read -r name cmd args; do
      [[ -z "$name" ]] && continue
      srv_names+=("$name")
      srv_command["$name"]="$cmd"
      srv_args["$name"]="$args"
    done < <(jq -r '
        ((.mcpServers // .servers // {}) | to_entries[] |
         [.key, (.value.command // "?"), ((.value.args // []) | join(" "))] | @tsv
        )' "$cfg" 2>/dev/null)
  else
    # Best-effort grep — extract server names by their object key. Less accurate.
    while IFS= read -r name; do
      [[ -n "$name" ]] && srv_names+=("$name") && srv_command["$name"]="?"
    done < <(grep -oE '"[A-Za-z0-9_\-]+"\s*:\s*\{' "$cfg" 2>/dev/null | sed -E 's/^"([^"]+)".*/\1/' | grep -vE '^(mcpServers|servers|env|args)$')
  fi

  for name in "${srv_names[@]}"; do
    total_servers=$((total_servers+1))
    cmd="${srv_command[$name]:-?}"
    args="${srv_args[$name]:-}"

    # Classify launch method
    case "$cmd" in
      npx)
        total_npx=$((total_npx+1))
        # Check for pinned version in args (@x.y.z or @^x.y.z)
        pinned=0
        if printf '%s' "$args" | grep -qE '@[~^=]?[0-9]+\.[0-9]+\.[0-9]+'; then
          pinned=1
          total_pinned=$((total_pinned+1))
        fi
        if [[ "$pinned" -eq 1 ]]; then
          emit_finding "$MODULE" "MEDIUM" "M.2.npx.pinned" \
            "MCP server '$name' launched via npx with pinned version: $cfg" \
            "Command: $cmd $args" \
            "Better than unpinned, but npx still re-resolves the registry. Prefer: install MCP server globally with audited version (npm i -g <pkg>@<ver>) and reference the absolute binary path." \
            "MCP marketplace poisoning (April 2026, OX Security)"
        else
          emit_finding "$MODULE" "HIGH" "M.2.npx.unpinned" \
            "MCP server '$name' launched via npx without pinned version: $cfg" \
            "Command: $cmd $args. npx fetches the latest matching package on every run — supply-chain attack window is permanent." \
            "Pin a specific version in args (e.g. \"@scope/server@1.2.3\"). Better: install globally with audited version: npm i -g <pkg>@<version>. Replace 'npx' with the absolute path to the installed binary." \
            "9 of 11 MCP marketplaces poisoned with malicious trial balloons (April 2026)"
        fi
        ;;
      uvx)
        total_uvx=$((total_uvx+1))
        emit_finding "$MODULE" "HIGH" "M.2.uvx" \
          "MCP server '$name' launched via uvx: $cfg" \
          "Command: $cmd $args. uvx fetches and executes Python packages on demand." \
          "Pin to specific version with uvx==<ver>. Better: install in a managed venv and reference the binary path." \
          "Same supply-chain risk class as npx"
        ;;
      docker)
        emit_finding "$MODULE" "INFO" "M.2.docker" \
          "MCP server '$name' runs in docker container (good — sandbox boundary)" \
          "Command: $cmd $args" "" ""
        ;;
      node|python|python3|ruby|/*)
        emit_finding "$MODULE" "INFO" "M.2.local" \
          "MCP server '$name' uses local interpreter or absolute path" \
          "Command: $cmd $args" "" ""
        ;;
      *)
        emit_finding "$MODULE" "MEDIUM" "M.2.unknown" \
          "MCP server '$name' uses unrecognized launcher: $cmd" \
          "Command: $cmd $args" \
          "Verify what this is. If it's a one-off tool fetched at runtime, treat as supply-chain risk." \
          ""
        ;;
    esac
  done

  unset srv_names srv_command srv_args

  # Plaintext secrets per server (extra check vs module B which only flagged file-level)
  if grep -qE '"(api[_-]?key|token|password|secret|auth|bearer)"\s*:\s*"[A-Za-z0-9_\-\.]{16,}"' "$cfg" 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "M.3.plaintext_secrets" \
      "MCP config contains plaintext secret(s): $cfg" \
      "Per-server env values are picked up by the launcher and inherited by every tool the server exposes." \
      "Migrate secrets to env-var injection from the host shell (set in shell rc gated to specific apps), or use a secrets manager (1Password CLI / Infisical) and reference via shell substitution at launch time." \
      "Trend Micro 2025 — 24,000+ secrets leaked via MCP configs on public GitHub"
  fi
done

# Summary finding
if [[ "$total_servers" -gt 0 ]]; then
  emit_finding "$MODULE" "INFO" "M.summary" \
    "Inventory: $total_servers MCP server(s) across configs — $total_npx via npx ($total_pinned pinned), $total_uvx via uvx" \
    "Each MCP server runs as a child process with the agent's privileges and can be invoked by tool calls." \
    "If any number above is non-zero for npx/uvx, supply-chain compromise of that package = RCE on this machine via the next agent invocation." \
    ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
