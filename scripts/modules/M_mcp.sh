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
: > "$FINDINGS_DIR/$MODULE.jsonl"

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
  done < <(dev_find "$p" 5 -name '.mcp.json')
done

total_servers=0
total_npx=0
total_uvx=0
total_pinned=0
total_remote=0

for cfg in "${MCP_CONFIGS[@]}"; do
  [[ -f "$cfg" ]] || continue

  emit_finding "$MODULE" "INFO" "M.1.found" "MCP config: $cfg" "" "" ""

  # Inventory each server as parallel arrays (names can repeat across project scopes).
  # Two extraction paths: jq (preferred) or a grep heuristic fallback.
  srv_scope=(); srv_names=(); srv_type=(); srv_cmd=(); srv_args=(); srv_url=()

  if [[ "$HAS_JQ" -eq 1 ]]; then
    # Top-level "mcpServers" (Claude Desktop / user scope in ~/.claude.json) or "servers"
    # (VS Code), plus per-project servers that ~/.claude.json keeps under .projects[path].
    # Fields are joined with \x1f, not tabs: tab is IFS whitespace, so an empty first
    # field (user scope) would collapse and shift every column.
    while IFS=$'\x1f' read -r scope name type cmd args url; do
      [[ -z "$name" ]] && continue
      srv_scope+=("$scope"); srv_names+=("$name"); srv_type+=("$type")
      srv_cmd+=("$cmd"); srv_args+=("$args"); srv_url+=("$url")
    done < <(jq -r '
        def rows($scope): to_entries[] | [$scope, .key, (.value.type // ""), (.value.command // ""),
          ((.value.args // []) | map(tostring) | join(" ")), (.value.url // "")] | join("\u001f");
        ((.mcpServers // .servers // {}) | rows("")),
        ((.projects // {}) | to_entries[] | .key as $p | (.value.mcpServers // {}) | rows($p))
      ' "$cfg" 2>/dev/null)
  else
    # Best-effort grep — extract server names by their object key. Less accurate.
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      srv_scope+=(""); srv_names+=("$name"); srv_type+=(""); srv_cmd+=("?"); srv_args+=(""); srv_url+=("")
    done < <(grep -oE '"[A-Za-z0-9_\-]+"\s*:\s*\{' "$cfg" 2>/dev/null | sed -E 's/^"([^"]+)".*/\1/' | grep -vE '^(mcpServers|servers|env|args|projects|headers)$')
  fi

  for i in "${!srv_names[@]}"; do
    total_servers=$((total_servers+1))
    name="${srv_names[$i]}"
    cmd="${srv_cmd[$i]}"
    args="${srv_args[$i]}"
    url="${srv_url[$i]}"
    where="$cfg"
    [[ -n "${srv_scope[$i]}" ]] && where="$cfg (project ${srv_scope[$i]})"

    # Remote servers have a URL instead of a command. Only the host is reported: paths and
    # query strings of remote MCP URLs often carry tokens.
    if [[ -z "$cmd" && -n "$url" ]] || [[ "${srv_type[$i]}" =~ ^(http|sse|streamable-http)$ ]]; then
      total_remote=$((total_remote+1))
      scheme="${url%%://*}"
      host="${url#*://}"; host="${host%%/*}"; host="${host%%\?*}"; host="${host##*@}"
      if [[ "$scheme" == "https" ]]; then
        emit_finding "$MODULE" "INFO" "M.2.remote" \
          "Remote MCP server '$name' (${srv_type[$i]:-http}): $where" \
          "Host: $host. Tool calls and their arguments are sent to this host." "" ""
      else
        emit_finding "$MODULE" "MEDIUM" "M.2.remote.insecure" \
          "Remote MCP server '$name' uses unencrypted ${scheme:-unknown}: $where" \
          "Host: $host. Tool calls, arguments and any auth headers travel in clear text." \
          "Switch the server URL to https, or remove the server." ""
      fi
      continue
    fi
    cmd="${cmd:-?}"
    # Full args stay in memory only: they routinely carry --api-key / Authorization
    # headers. Findings get the launcher and the package (first non-flag argument).
    pkg=""
    read -r -a arg_words <<<"$args"
    for a in "${arg_words[@]}"; do
      [[ "$a" == -* || "$a" == "run" ]] && continue
      pkg="$a"; break
    done
    launch="Launcher: $cmd  Package: ${pkg:-(none)}"

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
            "MCP server '$name' launched via npx with pinned version: $where" \
            "$launch" \
            "Better than unpinned, but npx still re-resolves the registry. Prefer: install MCP server globally with audited version (npm i -g <pkg>@<ver>) and reference the absolute binary path." \
            "MCP marketplace poisoning (April 2026, OX Security)"
        else
          emit_finding "$MODULE" "HIGH" "M.2.npx.unpinned" \
            "MCP server '$name' launched via npx without pinned version: $where" \
            "$launch. npx fetches the latest matching package on every run — supply-chain attack window is permanent." \
            "Pin a specific version in args (e.g. \"@scope/server@1.2.3\"). Better: install globally with audited version: npm i -g <pkg>@<version>. Replace 'npx' with the absolute path to the installed binary." \
            "9 of 11 MCP marketplaces poisoned with malicious trial balloons (April 2026)"
        fi
        ;;
      uvx)
        total_uvx=$((total_uvx+1))
        emit_finding "$MODULE" "HIGH" "M.2.uvx" \
          "MCP server '$name' launched via uvx: $where" \
          "$launch. uvx fetches and executes Python packages on demand." \
          "Pin to specific version with uvx==<ver>. Better: install in a managed venv and reference the binary path." \
          "Same supply-chain risk class as npx"
        ;;
      docker)
        emit_finding "$MODULE" "INFO" "M.2.docker" \
          "MCP server '$name' runs in docker container (good — sandbox boundary)" \
          "$launch" "" ""
        ;;
      node|python|python3|ruby|/*)
        emit_finding "$MODULE" "INFO" "M.2.local" \
          "MCP server '$name' uses local interpreter or absolute path" \
          "$launch" "" ""
        ;;
      *)
        emit_finding "$MODULE" "MEDIUM" "M.2.unknown" \
          "MCP server '$name' uses unrecognized launcher: $cmd" \
          "$launch" \
          "Verify what this is. If it's a one-off tool fetched at runtime, treat as supply-chain risk." \
          ""
        ;;
    esac
  done

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
    "Inventory: $total_servers MCP server(s) across configs — $total_npx via npx ($total_pinned pinned), $total_uvx via uvx, $total_remote remote" \
    "Each MCP server runs as a child process with the agent's privileges and can be invoked by tool calls." \
    "If any number above is non-zero for npx/uvx, supply-chain compromise of that package = RCE on this machine via the next agent invocation." \
    ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
