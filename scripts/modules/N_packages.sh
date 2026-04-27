#!/usr/bin/env bash
# Module N: Detection of known compromised packages and supply-chain attack indicators.
#
# Covers post-Nx attacks (2025-2026). Maintenance note: when a new IOC is published, add a
# row to NPM_COMPROMISED / PIP_COMPROMISED / EXT_COMPROMISED. Format: pkg|<ERE version match>|<incident summary>
#
# This module assumes nothing about runtime — it scans installed package lists and workspace
# manifests. It does not download anything or hit a network.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="N"
log "$MODULE" "Starting compromised packages detection..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# ---------- IOC database ----------
NPM_COMPROMISED=(
  'axios|^1\.14\.1$|axios 1.14.1 was malicious (March 2026 — Claude Code source-code leak campaign distributed RAT via npm dependency cascade between 00:21 and 03:29 UTC on 2026-03-31)'
  'axios|^0\.30\.4$|axios 0.30.4 was malicious (March 2026 — same campaign as 1.14.1)'
  '@bitwarden/cli|^2026\.4\.0$|@bitwarden/cli 2026.4.0 contained 10MB obfuscated malware specifically hunting for Claude Code, Cursor, Codex CLI, Aider, Kiro, Gemini CLI authentication state (Checkmarx, April 2026)'
  'nx|^20\.(9|10|11|12)\.0$|Nx s1ngularity attack (Aug 2025) — these versions published with credential-harvesting telemetry'
  'nx|^21\.[5-8]\.0$|Nx s1ngularity attack (Aug 2025) — these versions published with credential-harvesting telemetry'
)

PIP_COMPROMISED=(
  # Reserved for future entries — add as they appear publicly.
)

# Extension dir-name patterns. Format: name_glob|incident
EXT_COMPROMISED=(
  'prettier-vscode-plus*|prettier-vscode-plus VSCode extension (Nov 2025) — typo-squatted on official Prettier; deployed Anivia loader → OctoRAT RAT'
)

# ---------- N.1: npm globally-installed and workspace package.json ----------
if [[ "$HAS_NPM" -eq 1 ]]; then
  for entry in "${NPM_COMPROMISED[@]}"; do
    pkg="${entry%%|*}"; rest="${entry#*|}"
    ver_pat="${rest%%|*}"; rest="${rest#*|}"
    incident="$rest"

    # Global install
    found_line=$(npm ls -g --depth=0 --parseable=false 2>/dev/null | grep -E "${pkg//\//\\/}@" | head -1 || true)
    if [[ -n "$found_line" ]]; then
      found_ver=$(printf '%s' "$found_line" | grep -oE "${pkg//\//\\/}@[^[:space:]]+" | head -1 | sed -E "s|^${pkg//\//\\/}@||")
      if [[ -n "$found_ver" ]] && printf '%s' "$found_ver" | grep -qE "$ver_pat"; then
        emit_finding "$MODULE" "CRITICAL" "N.1.npm.global" \
          "Compromised npm package globally installed: $pkg@$found_ver" \
          "Detected via: npm ls -g $pkg." \
          "URGENT: (1) uninstall: npm uninstall -g \"$pkg\". (2) Treat machine as compromised — rotate ALL credentials this account had access to (GitHub, npm, AWS, SSH, crypto, AI provider keys). (3) Reinstall a known-safe version. (4) Audit shell init for shutdown injection (module G covers this)." \
          "$incident"
      fi
    fi
  done

  # Workspace package.json (declared dependencies — may not be installed but indicates exposure)
  for p in "${DEV_SEARCH_PATHS[@]}"; do
    [[ -d "$p" ]] || continue
    while IFS= read -r pj; do
      [[ -z "$pj" ]] && continue
      for entry in "${NPM_COMPROMISED[@]}"; do
        pkg="${entry%%|*}"; rest="${entry#*|}"
        ver_pat="${rest%%|*}"; rest="${rest#*|}"
        incident="$rest"
        # Match "<pkg>": "<optional ~^>VERSION"
        pkg_q=$(printf '%s' "$pkg" | sed 's|/|\\/|g')
        if grep -qE "\"${pkg_q}\"[[:space:]]*:[[:space:]]*\"[~^=]?($ver_pat)\"" "$pj" 2>/dev/null; then
          emit_finding "$MODULE" "CRITICAL" "N.1.npm.workspace" \
            "Workspace package.json references compromised version: $pkg ($ver_pat) in $pj" \
            "" \
            "Pin to a known-safe version, run npm install --ignore-scripts, audit recent activity. If installed/built since the compromise window — rotate credentials." \
            "$incident"
        fi
      done
    done < <(find "$p" -maxdepth 4 -name 'package.json' -not -path '*/node_modules/*' 2>/dev/null | head -200)
  done
fi

# ---------- N.2: pip ----------
pip_cmd=""
has pip3 && pip_cmd="pip3"
[[ -z "$pip_cmd" ]] && has pip && pip_cmd="pip"
if [[ -n "$pip_cmd" ]]; then
  for entry in "${PIP_COMPROMISED[@]}"; do
    pkg="${entry%%|*}"; rest="${entry#*|}"
    ver_pat="${rest%%|*}"; rest="${rest#*|}"
    incident="$rest"
    found_ver=$($pip_cmd show "$pkg" 2>/dev/null | awk '/^Version:/{print $2}')
    if [[ -n "$found_ver" ]] && printf '%s' "$found_ver" | grep -qE "$ver_pat"; then
      emit_finding "$MODULE" "CRITICAL" "N.2.pip" \
        "Compromised pip package installed: $pkg==$found_ver" \
        "" "$pip_cmd uninstall $pkg. Audit credentials." "$incident"
    fi
  done
fi

# ---------- N.3: VSCode / Cursor / Windsurf extensions ----------
EXT_DIRS=(
  "$HOME/.vscode/extensions"
  "$HOME/.vscode-server/extensions"
  "$HOME/.cursor/extensions"
  "$HOME/.windsurf/extensions"
  "$HOME/.config/Code/User/extensions"
  "$HOME/Library/Application Support/Code/User/extensions"
)
for d in "${EXT_DIRS[@]}"; do
  [[ -d "$d" ]] || continue
  for entry in "${EXT_COMPROMISED[@]}"; do
    glob="${entry%%|*}"
    incident="${entry#*|}"
    found=$(find "$d" -maxdepth 2 -type d -iname "$glob" 2>/dev/null | head -3)
    if [[ -n "$found" ]]; then
      emit_finding "$MODULE" "CRITICAL" "N.3.ext" \
        "Compromised IDE extension installed: $glob" \
        "Path(s):\n$found" \
        "Remove immediately: code --uninstall-extension <id> (or cursor --uninstall-extension). Then: rm -rf the directory. Treat machine as compromised — rotate credentials." \
        "$incident"
    fi
  done
done

# ---------- N.4: Recently-added user-bin binaries (low-confidence IOC) ----------
new_bin_count=0
for d in "$HOME/bin" "$HOME/.local/bin" "$HOME/.bun/bin" "$HOME/.cargo/bin" "$HOME/go/bin"; do
  [[ -d "$d" ]] || continue
  while IFS= read -r f; do
    [[ -n "$f" ]] && new_bin_count=$((new_bin_count+1))
  done < <(find "$d" -maxdepth 1 -type f -mtime -30 2>/dev/null)
done
if [[ "$new_bin_count" -gt 0 ]]; then
  emit_finding "$MODULE" "INFO" "N.4.newbin" \
    "$new_bin_count user-bin binary file(s) added/modified in last 30 days" \
    "Recent additions can be legitimate installs OR adversarial drops. Heuristic, not conclusive." \
    "Review: find ~/bin ~/.local/bin ~/.bun/bin ~/.cargo/bin ~/go/bin -type f -mtime -30 -ls. Verify each against an expected install command." \
    ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
