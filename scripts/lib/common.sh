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

# Finding files rendered into the reports, in order. X holds run-level context (scanned
# roots) written by run-audit.sh itself.
REPORT_MODULES="A B C D E F G H I J K L M N P X"
export REPORT_MODULES

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

# --- Shared detection patterns (ERE; tests/test_patterns.sh exercises these variables) ---
# Classic prompt-injection phrasing in agent rules files (match case-insensitively).
INJECTION_RE='ignore (all )?(previous|prior|above|earlier) (instructions?|rules|context)|disregard (the )?(above|earlier|prior) (rules|instructions|context)|new instructions:|you are now (a|an|the) '
# Instructions that switch off human confirmation. Bounded: "never skip code review" is fine.
BYPASS_RE='(skip|bypass|disable)[[:space:]]+(the[[:space:]]+|all[[:space:]]+|any[[:space:]]+)?(user[[:space:]]+)?(confirmations?|approvals?|permission( prompts?|s)?|safety( checks?| prompts?)?)'
# Covert-action wording in skills: an instruction to keep the user in the dark. Bare
# "exfiltrate" or "without asking" fired on threat descriptions and on safety rules such
# as "never run --force without asking", so both need the explicit "the user" object.
EXFIL_RE='without (telling|notifying|informing|asking) the user|do not (tell|inform|notify) the user|hide (this|it) from the user'
# Download piped into a shell or interpreter, or dropped into /tmp.
NETEXEC_RE='(curl|wget|nc)[[:space:]][^|]*\|[[:space:]]*(sudo[[:space:]]+)?((ba|z|da)?sh|python3?)([[:space:];]|$)|(curl|wget)[[:space:]].*>[[:space:]]*/tmp/'
# Zero-width / bidi-control characters as UTF-8 bytes (use with LC_ALL=C grep -E):
# U+200B ZWSP, U+200C ZWNJ, U+200E/F LRM/RLM, U+202A–202E embeddings/overrides,
# U+2060–2064 word joiner/invisible operators, U+2066–2069 isolates. U+200D (ZWJ) is left
# out on purpose: every compound emoji contains it.
ZWBIDI_RE=$'\xe2\x80[\x8b\x8c\x8e\x8f\xaa\xab\xac\xad\xae]|\xe2\x81[\xa0\xa1\xa2\xa3\xa4\xa6\xa7\xa8\xa9]'
export INJECTION_RE BYPASS_RE EXFIL_RE NETEXEC_RE ZWBIDI_RE

# --- Claude Code settings risk flags ---
# Prints space-separated flags for risky settings in a Claude Code settings file
# (current schema: permissions.allow / permissions.defaultMode, env, hooks):
#   bypass     permissions.defaultMode == "bypassPermissions"
#   bashall    permissions.allow grants every Bash command ("Bash", "Bash(*)", "Bash(:*)")
#   baseurl    env.ANTHROPIC_BASE_URL set (API traffic, including the key, goes elsewhere)
#   allmcp     enableAllProjectMcpServers: true (every repo .mcp.json server auto-approved)
#   keyhelper  apiKeyHelper set (a command run to obtain the API key)
#   hooks      hooks defined
#   legacy     legacy alwaysAllow / allowedTools keys
claude_settings_flags() {
  local f="$1"
  [[ -r "$f" ]] || return 0
  if [[ "$HAS_JQ" -eq 1 ]] && jq empty "$f" >/dev/null 2>&1; then
    jq -r '[
      (if .permissions.defaultMode? == "bypassPermissions" then "bypass" else empty end),
      (if ([.permissions.allow? // [] | .[] | strings
            | select(. == "Bash" or . == "Bash(*)" or . == "Bash(:*)")] | length) > 0
       then "bashall" else empty end),
      (if .env.ANTHROPIC_BASE_URL? then "baseurl" else empty end),
      (if .enableAllProjectMcpServers? == true then "allmcp" else empty end),
      (if .apiKeyHelper? then "keyhelper" else empty end),
      (if .hooks? and (.hooks | length) > 0 then "hooks" else empty end),
      (if has("alwaysAllow") or has("allowedTools") then "legacy" else empty end)
    ] | join(" ")' "$f" 2>/dev/null
    return 0
  fi
  local out=""
  grep -qE '"defaultMode"[[:space:]]*:[[:space:]]*"bypassPermissions"' "$f" && out="$out bypass"
  grep -qE '"Bash(\(:?\*\))?"' "$f" && out="$out bashall"
  grep -q '"ANTHROPIC_BASE_URL"' "$f" && out="$out baseurl"
  grep -qE '"enableAllProjectMcpServers"[[:space:]]*:[[:space:]]*true' "$f" && out="$out allmcp"
  grep -q '"apiKeyHelper"' "$f" && out="$out keyhelper"
  grep -q '"hooks"' "$f" && out="$out hooks"
  grep -qE '"(alwaysAllow|allowedTools)"' "$f" && out="$out legacy"
  printf '%s' "${out# }"
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

# --- Project roots scanned by repo-level checks ---
# Guessing directory names (~/projects, ~/code, ...) missed most real layouts, so roots come
# from where agents actually ran:
#   - AUDIT_DEV_PATHS (colon-separated) — when set, used exclusively;
#   - otherwise ~/.claude.json .projects keys and Codex [projects."<path>"] entries, plus
#     the conventional names. Gemini CLI keeps no project list, so it adds nothing.
# Directories with more than 3 known projects under the same parent collapse to that
# parent; $HOME and its ancestors are never roots (home-level files are checked directly);
# roots nested in another root are dropped; at most DEV_ROOTS_CAP roots are kept.
DEV_ROOTS_CAP=60
export DEV_ROOTS_CAPPED=0  # set by build_dev_search_paths, read by run-audit.sh
DEFAULT_DEV_DIRS=("$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work" "$HOME/repos" "$HOME/src")

_agent_project_dirs() {
  if [[ -f "$HOME/.claude.json" ]]; then
    if [[ "$HAS_JQ" -eq 1 ]]; then
      jq -r '.projects // {} | keys[]' "$HOME/.claude.json" 2>/dev/null
    elif [[ "$HAS_PYTHON3" -eq 1 ]]; then
      python3 -c 'import json,sys
try: print("\n".join(json.load(open(sys.argv[1])).get("projects", {}).keys()))
except Exception: pass' "$HOME/.claude.json" 2>/dev/null
    fi
  fi
  [[ -f "$HOME/.codex/config.toml" ]] && \
    sed -nE 's/^\[projects\."([^"]+)"\][[:space:]]*$/\1/p' "$HOME/.codex/config.toml" 2>/dev/null
  return 0
}

build_dev_search_paths() {
  local cand=() p
  if [[ -n "${AUDIT_DEV_PATHS:-}" ]]; then
    IFS=: read -r -a cand <<<"$AUDIT_DEV_PATHS"
  else
    while IFS= read -r p; do [[ -n "$p" ]] && cand+=("$p"); done < <(_agent_project_dirs)
    cand+=("${DEFAULT_DEV_DIRS[@]}")
  fi
  DEV_SEARCH_PATHS=()
  DEV_ROOTS_CAPPED=0
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if [[ "${#DEV_SEARCH_PATHS[@]}" -ge "$DEV_ROOTS_CAP" ]]; then DEV_ROOTS_CAPPED=1; break; fi
    DEV_SEARCH_PATHS+=("$p")
  done < <(
    for p in "${cand[@]}"; do [[ -d "$p" ]] && printf '%s\n' "${p%/}"; done | awk -v home="$HOME" '
      { p = $0
        if (p == "" || p == home || index(home "/", p "/") == 1) next   # $HOME or an ancestor
        par = p; sub(/\/[^\/]*$/, "", par)
        n++; cand[n] = p; parent[n] = par; cnt[par]++ }
      END {
        for (i = 1; i <= n; i++) {
          r = cand[i]
          if (cnt[parent[i]] > 3 && parent[i] != home && index(home "/", parent[i] "/") != 1) r = parent[i]
          if (!(r in seen)) { seen[r] = 1; out[++m] = r }
        }
        for (i = 1; i <= m; i++) {          # drop roots nested inside another root
          nested = 0
          for (j = 1; j <= m; j++) if (i != j && index(out[i], out[j] "/") == 1) nested = 1
          if (!nested) print out[i]
        }
      }' | sort
  )
}
build_dev_search_paths

# dev_find <root> <maxdepth> <find expression...> — find that never descends into
# node_modules or .git. Pruning (instead of -not -path filtering) is ~15x faster on real
# workspaces. Checks that need to look inside node_modules use plain find.
dev_find() {
  local root="$1" depth="$2"; shift 2
  find "$root" -maxdepth "$depth" \( -name node_modules -o -name .git \) -prune -o \( "$@" \) -print 2>/dev/null
}

export -f has json_escape emit_finding untrusted_text untrusted_snippet claude_settings_flags file_perm_octal file_mtime_unix \
          count_matches count_pattern_matches json_decode_field \
          ssh_key_has_passphrase _agent_project_dirs build_dev_search_paths dev_find \
          log warn err

# Secret patterns and redaction, needed by emit_finding. secrets.sh does not source
# common.sh, so there is no cycle.
source "$(dirname "${BASH_SOURCE[0]}")/secrets.sh"
