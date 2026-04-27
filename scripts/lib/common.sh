#!/usr/bin/env bash
# Common helpers for ai-agent-audit modules.
# Sourced by all module scripts. Don't run directly.

# --- Output dirs ---
AUDIT_DIR="${AUDIT_DIR:-$HOME/.ai-agent-audit}"
FINDINGS_DIR="$AUDIT_DIR/findings"
mkdir -p "$FINDINGS_DIR"

# --- OS detection ---
case "$(uname -s)" in
  Darwin) OS="macos" ;;
  Linux)  OS="linux" ;;
  *)      OS="unknown" ;;
esac
export OS

# --- Tool availability ---
has() { command -v "$1" >/dev/null 2>&1; }
HAS_JQ=$(has jq && echo 1 || echo 0)
HAS_SQLITE=$(has sqlite3 && echo 1 || echo 0)
HAS_GH=$(has gh && echo 1 || echo 0)
HAS_NPM=$(has npm && echo 1 || echo 0)
HAS_AWS=$(has aws && echo 1 || echo 0)
export HAS_JQ HAS_SQLITE HAS_GH HAS_NPM HAS_AWS

# --- Logging ---
log()    { printf '\033[1;34m[%s]\033[0m %s\n' "$1" "$2" >&2; }
warn()   { printf '\033[1;33m[WARN]\033[0m %s\n' "$1" >&2; }
err()    { printf '\033[1;31m[ERR]\033[0m %s\n' "$1" >&2; }

# --- Findings emitter ---
# emit_finding <module> <severity> <id> <title> <evidence> <remediation> [incident_ref]
# Severities: CRITICAL | HIGH | MEDIUM | LOW | INFO
# Outputs JSON line to $FINDINGS_DIR/<module>.jsonl
emit_finding() {
  local module="$1" severity="$2" id="$3" title="$4" evidence="$5" remediation="$6" incident="${7:-}"
  local out="$FINDINGS_DIR/$module.jsonl"
  # JSON-escape minimal: replace " with \", and \n with literal \n in fields.
  esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'; }
  printf '{"module":"%s","severity":"%s","id":"%s","title":"%s","evidence":"%s","remediation":"%s","incident":"%s","ts":"%s"}\n' \
    "$(esc "$module")" "$(esc "$severity")" "$(esc "$id")" \
    "$(esc "$title")" "$(esc "$evidence")" "$(esc "$remediation")" \
    "$(esc "$incident")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "$out"
}

# --- Helpers for safe checks ---

# Check if file exists and has restricted permissions (owner-only read for keys)
file_perm_octal() {
  local f="$1"
  if [[ "$OS" == "macos" ]]; then
    stat -f '%Lp' "$f" 2>/dev/null
  else
    stat -c '%a' "$f" 2>/dev/null
  fi
}

# Test if SSH private key has a passphrase. Returns 0 if has passphrase, 1 if no passphrase, 2 if can't determine.
ssh_key_has_passphrase() {
  local key="$1"
  [[ -r "$key" ]] || return 2
  # ssh-keygen -y reads private key; with -P "" it tries empty passphrase. If that succeeds, no passphrase.
  if ssh-keygen -y -P '' -f "$key" >/dev/null 2>&1; then
    return 1  # no passphrase
  fi
  # Could be passphrase-protected OR malformed. Check first line for "ENCRYPTED" marker.
  if head -n 5 "$key" 2>/dev/null | grep -qiE 'ENCRYPTED|bcrypt'; then
    return 0  # has passphrase
  fi
  return 2
}

# Lookup whether `nx` is installed in any project dir under HOME and at what version
# (Nx s1ngularity check)
find_nx_versions() {
  if [[ "$HAS_NPM" -eq 1 ]]; then
    # Look for package.json files under common dev locations, excluding node_modules
    local search_paths=("$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work" "$HOME/repos" "$HOME/src")
    for p in "${search_paths[@]}"; do
      [[ -d "$p" ]] || continue
      find "$p" -maxdepth 4 -name 'package.json' -not -path '*/node_modules/*' 2>/dev/null | \
      while read -r pj; do
        if grep -q '"nx"' "$pj" 2>/dev/null; then
          local ver
          ver=$(grep -oE '"nx"[[:space:]]*:[[:space:]]*"[^"]*"' "$pj" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
          printf '%s\t%s\n' "$pj" "$ver"
        fi
      done
    done
  fi
}

# Compromised Nx version range check (s1ngularity attack August 2025)
is_nx_compromised_version() {
  local v="$1"
  # Strip ^/~/= prefixes
  v="${v#^}"; v="${v#~}"; v="${v#=}"
  # Compromised: 20.9.0 - 21.8.0
  case "$v" in
    20.9.0|20.10.0|20.11.0|20.12.0|21.5.0|21.6.0|21.7.0|21.8.0) return 0 ;;
    *) return 1 ;;
  esac
}

export -f has emit_finding file_perm_octal ssh_key_has_passphrase find_nx_versions is_nx_compromised_version log warn err
