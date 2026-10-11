#!/usr/bin/env bash
# Common helpers for ai-agent-audit modules.
# Sourced by all module scripts. Don't run directly.

# bash >= 4.4: associative arrays, mapfile, and empty "${arr[@]}" under set -u (an
# "unbound variable" error before 4.4). Stock macOS /bin/bash is 3.2.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  printf 'ai-agent-audit needs bash >= 4.4 (found %s).\n' "$BASH_VERSION" >&2
  printf 'macOS: brew install bash, then run: "$(brew --prefix)/bin/bash" %s\n' "$0" >&2
  exit 2
fi

# --- Output dirs ---
AUDIT_DIR="${AUDIT_DIR:-$HOME/.ai-agent-audit}"
FINDINGS_DIR="$AUDIT_DIR/findings"
export AUDIT_DIR FINDINGS_DIR
# Reports hold paths and fingerprints; other local users have no business reading them.
umask 077
mkdir -p "$FINDINGS_DIR"
chmod 700 "$AUDIT_DIR" 2>/dev/null

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
HAS_PYTHON3=$(has python3 && echo 1 || echo 0)
HAS_PERL=$(has perl && echo 1 || echo 0)
export HAS_JQ HAS_SQLITE HAS_GH HAS_NPM HAS_AWS HAS_PYTHON3 HAS_PERL

# --- Logging ---
log()    { printf '\033[1;34m[%s]\033[0m %s\n' "$1" "$2" >&2; }
warn()   { printf '\033[1;33m[WARN]\033[0m %s\n' "$1" >&2; }
err()    { printf '\033[1;31m[ERR]\033[0m %s\n' "$1" >&2; }

# --- JSON string escaping ---
# Prints the body of a JSON string literal (no surrounding quotes) for any input bytes.
# jq when present (exact, keeps control chars as \uXXXX); otherwise one portable awk pass
# that escapes \ " tab CR LF and drops the remaining C0 controls and DEL. No GNU-only sed.
json_escape() {
  if [[ "$HAS_JQ" -eq 1 ]]; then
    printf '%s' "$1" | jq -Rs . | sed -e 's/^"//' -e 's/"$//'
    return
  fi
  # Literal replacement via index/substr: gsub() replacement strings treat backslashes
  # differently in mawk, gawk, BWK awk (macOS) and busybox, so they are avoided here.
  printf '%s' "$1" | LC_ALL=C awk '
    function rep(s, from, to,   out, i) {
      out = ""
      while ((i = index(s, from)) > 0) {
        out = out substr(s, 1, i - 1) to
        s = substr(s, i + length(from))
      }
      return out s
    }
    BEGIN { ORS = "" }
    {
      line = rep($0, "\\", "\\\\")
      line = rep(line, "\"", "\\\"")
      line = rep(line, "\t", "\\t")
      line = rep(line, "\r", "\\r")
      gsub(/[\001-\010\013\014\016-\037\177]/, "", line)
      if (NR > 1) printf "\\n"
      printf "%s", line
    }'
}

# --- Findings emitter ---
# emit_finding <module> <severity> <id> <title> <evidence> <remediation> [incident_ref]
# Severities: CRITICAL | HIGH | MEDIUM | LOW | INFO
# Outputs JSON line to $FINDINGS_DIR/<module>.jsonl
emit_finding() {
  local module="$1" severity="$2" id="$3" title="$4" evidence="$5" remediation="$6" incident="${7:-}"
  local out="$FINDINGS_DIR/$module.jsonl"
  # Safety net: no module can persist a raw credential through finding text.
  title=$(redact_secrets_in_text "$title")
  evidence=$(redact_secrets_in_text "$evidence")
  remediation=$(redact_secrets_in_text "$remediation")
  printf '{"module":"%s","severity":"%s","id":"%s","title":"%s","evidence":"%s","remediation":"%s","incident":"%s","ts":"%s"}\n' \
    "$(json_escape "$module")" "$(json_escape "$severity")" "$(json_escape "$id")" \
    "$(json_escape "$title")" "$(json_escape "$evidence")" "$(json_escape "$remediation")" \
    "$(json_escape "$incident")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
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

# File mtime as unix timestamp (cross-platform)
file_mtime_unix() {
  local f="$1"
  if [[ "$OS" == "macos" ]]; then
    stat -f '%m' "$f" 2>/dev/null
  else
    stat -c '%Y' "$f" 2>/dev/null
  fi
}

# Safe count of lines matching pattern. Always returns a clean integer (0 on error/no match).
# Replacement for the `$(grep -c '...' file 2>/dev/null || echo 0)` pattern, which produced "0\n0"
# when grep printed "0\n" on no matches AND fell through to the || branch (exit 1).
count_matches() {
  local pattern="$1" file="$2" flags="${3:-E}"
  local count=0
  if [[ -r "$file" ]]; then
    count=$(grep -c -"$flags" "$pattern" "$file" 2>/dev/null) || count=0
  fi
  printf '%s' "${count:-0}" | tr -d '[:space:]'
}

# Count individual occurrences of a pattern (not just matching lines).
count_pattern_matches() {
  local pattern="$1" file="$2"
  local count=0
  if [[ -r "$file" ]]; then
    count=$(grep -oE "$pattern" "$file" 2>/dev/null | wc -l)
  fi
  printf '%s' "${count:-0}" | tr -d '[:space:]'
}

# Decode a single field from a JSON object string. Tries jq → python3 → perl → sed (lossy).
# Usage: json_decode_field "$json_line" "remediation"
# Critical: handles escaped quotes \" inside the value (which sed `[^"]*` cannot).
json_decode_field() {
  local json="$1" field="$2"
  if [[ "$HAS_JQ" -eq 1 ]]; then
    printf '%s' "$json" | jq -r --arg f "$field" '.[$f] // ""' 2>/dev/null
    return
  fi
  if [[ "$HAS_PYTHON3" -eq 1 ]]; then
    printf '%s' "$json" | python3 -c "import sys,json
try:
  d=json.loads(sys.stdin.read())
  sys.stdout.write(str(d.get('$field','')))
except Exception: pass" 2>/dev/null
    return
  fi
  if [[ "$HAS_PERL" -eq 1 ]]; then
    printf '%s' "$json" | perl -MJSON::PP -e 'my $j=JSON::PP->new->decode(<STDIN>); print $j->{"'"$field"'"} // "";' 2>/dev/null
    return
  fi
  # Fallback: greedy sed that handles escaped quotes (best-effort, not bulletproof).
  # Match anything that's not a bare quote, allowing \" inside.
  printf '%s' "$json" | sed -nE 's/.*"'"$field"'":"((\\.|[^"\\])*)".*/\1/p' \
    | sed -e 's/\\"/"/g' -e 's/\\n/\n/g' -e 's/\\t/\t/g' -e 's/\\\\/\\/g'
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

# --- Untrusted content ---
# Text read from files an attacker may control (repo rules files, hook commands, plists)
# ends up in reports that an AI agent later reads. It is redacted first (so truncation
# cannot cut a token below the pattern length and leak its prefix), stripped of control
# characters, cut to max characters and labelled.
UNTRUSTED_LABEL="[untrusted content]"
untrusted_text() {
  local text="$1" max="${2:-80}"
  text=$(redact_secrets_in_text "$text")
  text=$(printf '%s' "$text" | tr -d '\000-\037\177')
  if (( ${#text} > max )); then
    text="${text:0:max}…"
  fi
  printf '%s %s' "$UNTRUSTED_LABEL" "$text"
}

# untrusted_snippet <file> <line-number> [max] → "<file>:<n> [untrusted content] <snippet>"
untrusted_snippet() {
  local file="$1" n="$2" max="${3:-80}"
  printf '%s:%s %s' "$file" "$n" "$(untrusted_text "$(sed -n "${n}p" "$file" 2>/dev/null)" "$max")"
}

# Standard search paths for user dev projects (used by multiple modules).
DEV_SEARCH_PATHS=("$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work" "$HOME/repos" "$HOME/src")
export DEV_SEARCH_PATHS

export -f has json_escape emit_finding untrusted_text untrusted_snippet file_perm_octal file_mtime_unix \
          count_matches count_pattern_matches json_decode_field \
          ssh_key_has_passphrase find_nx_versions is_nx_compromised_version \
          log warn err

# Secret patterns and redaction, needed by emit_finding. secrets.sh does not source
# common.sh, so there is no cycle.
source "$(dirname "${BASH_SOURCE[0]}")/secrets.sh"
