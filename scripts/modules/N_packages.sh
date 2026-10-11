#!/usr/bin/env bash
# Module N: Detection of known compromised packages and supply-chain attack indicators.
#
# Covers post-Nx attacks (2025-2026). Maintenance note: when a new IOC is published, add a
# row to NPM_COMPROMISED / PIP_COMPROMISED / EXT_COMPROMISED. Format: pkg|<unanchored ERE version>|<incident summary>
#
# This module assumes nothing about runtime — it scans installed package lists and workspace
# manifests. It does not download anything or hit a network.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="N"
log "$MODULE" "Starting compromised packages detection..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# ---------- IOC database ----------
# The single list of compromised versions (module G no longer keeps its own Nx list).
# Version patterns are unanchored EREs; callers anchor them with ^(...)$ when comparing a
# whole version, and embed them as-is inside larger patterns.
NPM_COMPROMISED=(
  'axios|1\.14\.1|axios 1.14.1 was malicious (March 2026 — Claude Code source-code leak campaign distributed RAT via npm dependency cascade between 00:21 and 03:29 UTC on 2026-03-31)'
  'axios|0\.30\.4|axios 0.30.4 was malicious (March 2026 — same campaign as 1.14.1)'
  '@bitwarden/cli|2026\.4\.0|@bitwarden/cli 2026.4.0 contained 10MB obfuscated malware specifically hunting for Claude Code, Cursor, Codex CLI, Aider, Kiro, Gemini CLI authentication state (Checkmarx, April 2026)'
  'nx|20\.(9|10|11|12)\.0|Nx s1ngularity attack (Aug 2025) — these versions published with credential-harvesting telemetry'
  'nx|21\.[5-8]\.0|Nx s1ngularity attack (Aug 2025) — these versions published with credential-harvesting telemetry'
)

PIP_COMPROMISED=(
  # Reserved for future entries — add as they appear publicly.
)

# Extension dir-name globs. Installed extensions live in <publisher>.<name>-<version>/.
# Format: name_glob|incident
EXT_COMPROMISED=(
  '*.prettier-vscode-plus-*|prettier-vscode-plus VSCode extension (Nov 2025) — typo-squatted on official Prettier; deployed Anivia loader → OctoRAT RAT'
)

# Escape ERE metacharacters in a package name (scoped names contain / and sometimes .).
ere_quote() { printf '%s' "$1" | sed 's/[][\.*^$()+?{}|]/\\&/g'; }

# Installed version of <pkg> under <project-dir>: node_modules/<pkg>/package.json, else
# package-lock.json (v2/v3 "packages" map, including nested node_modules). One per line.
resolved_versions() {
  local dir="$1" pkg="$2" pkg_re
  if [[ -f "$dir/node_modules/$pkg/package.json" ]]; then
    grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$dir/node_modules/$pkg/package.json" \
      | head -1 | sed -E 's/.*"([^"]+)"$/\1/'
  fi
  [[ -f "$dir/package-lock.json" ]] || return 0
  # Cheap fixed-string check first: running jq on every lockfile for every IOC row was
  # the slowest part of the module on real workspaces.
  grep -qF "node_modules/$pkg\"" "$dir/package-lock.json" 2>/dev/null || return 0
  if [[ "$HAS_JQ" -eq 1 ]]; then
    jq -r --arg p "$pkg" '.packages // {} | to_entries[]
      | select(.key == "node_modules/" + $p or (.key | endswith("/node_modules/" + $p)))
      | .value.version // empty' "$dir/package-lock.json" 2>/dev/null
  else
    pkg_re=$(ere_quote "$pkg")
    grep -A4 -E "\"([^\"]*/)?node_modules/${pkg_re}\"[[:space:]]*:[[:space:]]*\\{" "$dir/package-lock.json" 2>/dev/null \
      | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/'
  fi
}

# ---------- N.1: npm — global installs ----------
if [[ "$HAS_NPM" -eq 1 ]]; then
  global_ls=$(npm ls -g --depth=0 2>/dev/null || true)
  for entry in "${NPM_COMPROMISED[@]}"; do
    pkg="${entry%%|*}"; rest="${entry#*|}"
    ver_pat="${rest%%|*}"; incident="${rest#*|}"
    pkg_re=$(ere_quote "$pkg")
    # Anchor the name: "nx@" must not match "lynx@" in the tree output.
    match=$(printf '%s\n' "$global_ls" | grep -oE "(^|[[:space:]─└├│])${pkg_re}@[^[:space:]]+" | head -1)
    found_ver="${match##*@}"
    if [[ -n "$found_ver" ]] && printf '%s' "$found_ver" | grep -qE "^(${ver_pat})$"; then
      emit_finding "$MODULE" "CRITICAL" "N.1.npm.global" \
        "Compromised npm package globally installed: $pkg@$found_ver" \
        "Detected via: npm ls -g --depth=0." \
        "URGENT: (1) uninstall: npm uninstall -g \"$pkg\". (2) Treat machine as compromised — rotate ALL credentials this account had access to (GitHub, npm, AWS, SSH, crypto, AI provider keys). (3) Reinstall a known-safe version. (4) Audit shell init for shutdown injection (module G covers this)." \
        "$incident"
    fi
  done
fi

# ---------- N.1: npm — workspace projects (declared spec AND resolved version) ----------
# No npm needed: manifests, lockfiles and node_modules are read as files.
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r pj; do
    [[ -z "$pj" ]] && continue
    dir=$(dirname "$pj")
    for entry in "${NPM_COMPROMISED[@]}"; do
      pkg="${entry%%|*}"; rest="${entry#*|}"
      ver_pat="${rest%%|*}"; incident="${rest#*|}"
      pkg_re=$(ere_quote "$pkg")
      # Declared: "<pkg>": "<optional ~^=>VERSION"
      if grep -qE "\"${pkg_re}\"[[:space:]]*:[[:space:]]*\"[~^=]?(${ver_pat})\"" "$pj" 2>/dev/null; then
        emit_finding "$MODULE" "CRITICAL" "N.1.npm.workspace" \
          "Workspace package.json references compromised version: $pkg in $pj" \
          "Declared version matches ${ver_pat//\\/}." \
          "Pin to a known-safe version, run npm install --ignore-scripts, audit recent activity. If installed/built since the compromise window — rotate credentials." \
          "$incident"
      fi
      # Resolved: what is (or was locked to be) actually installed — catches ^1.14.0 → 1.14.1.
      while IFS= read -r v; do
        [[ -z "$v" ]] && continue
        if printf '%s' "$v" | grep -qE "^(${ver_pat})$"; then
          emit_finding "$MODULE" "CRITICAL" "N.1.npm.resolved" \
            "Compromised version installed or locked: $pkg@$v in $dir" \
            "Found in node_modules/$pkg/package.json or package-lock.json." \
            "Treat this project as compromised: delete node_modules, pin a safe version, reinstall with --ignore-scripts, and rotate every credential reachable from this machine if it was installed or built here." \
            "$incident"
          break
        fi
      done < <(resolved_versions "$dir" "$pkg" | sort -u)
    done
  done < <(dev_find "$p" 4 -name 'package.json' | head -200)
done

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
    if [[ -n "$found_ver" ]] && printf '%s' "$found_ver" | grep -qE "^(${ver_pat})$"; then
      emit_finding "$MODULE" "CRITICAL" "N.2.pip" \
        "Compromised pip package installed: $pkg==$found_ver" \
        "" "$pip_cmd uninstall $pkg. Audit credentials." "$incident"
    fi
  done
fi

# ---------- N.3: VSCode / Cursor / Windsurf extensions ----------
EXT_DIRS=(
  "$HOME/.vscode/extensions"
  "$HOME/.vscode-insiders/extensions"
  "$HOME/.vscode-server/extensions"
  "$HOME/.cursor/extensions"
  "$HOME/.windsurf/extensions"
)
for d in "${EXT_DIRS[@]}"; do
  [[ -d "$d" ]] || continue
  for entry in "${EXT_COMPROMISED[@]}"; do
    glob="${entry%%|*}"
    incident="${entry#*|}"
    found=$(find "$d" -maxdepth 1 -type d -iname "$glob" 2>/dev/null | head -3)
    if [[ -n "$found" ]]; then
      emit_finding "$MODULE" "CRITICAL" "N.3.ext" \
        "Compromised IDE extension installed: $glob" \
        "Path(s):"$'\n'"$found" \
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
