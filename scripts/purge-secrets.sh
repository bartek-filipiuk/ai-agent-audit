#!/usr/bin/env bash
# purge-secrets.sh — find and optionally remove lines containing real credentials
# from local history files and AI session storage.
#
# Default behaviour: DRY-RUN (only reports). Pass --purge to actually delete.
#
# Sources scanned:
#   - ~/.bash_history
#   - ~/.zsh_history (if present)
#   - ~/.claude/history.jsonl
#   - ~/.claude/projects/*/sessions/*.jsonl
#   - ~/.config/Cursor/User/globalStorage/state.vscdb        (only with --include-cursor)
#   - ~/.config/Cursor/User/workspaceStorage/                (only with --include-cursor)
#
# Detection logic:
#   - HIGH_CONFIDENCE patterns: AWS keys, GitHub PATs, OpenAI/Anthropic/HF/Replicate,
#     Slack tokens, Google API, DigitalOcean, npm, Stripe live, GitLab. Anything
#     matching these is treated as a real credential.
#   - DB connection strings (postgres/mysql/mongo/redis/amqp with embedded password)
#     are reported only if the host is NOT local (excludes localhost, 127.x, 0.0.0.0,
#     host.docker.internal, db, postgres). Local docker dev URLs are silently skipped.
#   - JWTs are NOT flagged by default (too high false-positive rate). Pass
#     --include-jwt to also flag them.
#
# Backups: every modified file is copied to <file>.bak.<TIMESTAMP> before edit.

set -u

# --- Patterns ---
HIGH_CONFIDENCE='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|gho_[A-Za-z0-9]{30,}|ghu_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|ghr_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{40,}|sk-proj-[A-Za-z0-9_-]{40,}|sk-svcacct-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|xoxb-[0-9]{10,}-[0-9]+-[A-Za-z0-9]{20,}|xoxp-[0-9]{10,}-[0-9]+-[A-Za-z0-9]{20,}|hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|hf_[A-Za-z0-9]{30,}|r8_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}|dop_v1_[A-Fa-f0-9]{64}|npm_[A-Za-z0-9]{36}|pypi-AgEIc[A-Za-z0-9_-]{20,}'

DB_URL_PATTERN='(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqps?)://[A-Za-z0-9._%+-]+:[^@[:space:]"'"'"']+@[A-Za-z0-9._-]+'

LOCAL_HOSTS_RE='@(localhost|127\.0\.0\.[0-9]+|0\.0\.0\.0|::1|host\.docker\.internal|db|postgres|mysql|mongo|redis|host)([:/]|$)'

JWT_PATTERN='eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}'

# --- Args ---
MODE="dryrun"
INCLUDE_CURSOR=0
INCLUDE_JWT=0
NO_PROMPT=0

usage() {
  cat <<EOF
Usage: $0 [--purge] [--include-cursor] [--include-jwt] [--no-prompt]

  --purge            Actually delete matching lines / files. Without this, runs dry-run.
  --include-cursor   Also wipe ~/.config/Cursor/User/globalStorage/state.vscdb and
                     workspaceStorage/ (moved to *.purged-DATE backups, NOT deleted).
  --include-jwt      Also flag JWT tokens (eyJ...). Default: skipped (high FP rate).
  --no-prompt        Skip the confirmation prompt before purge mode.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)          MODE="purge"; shift ;;
    --include-cursor) INCLUDE_CURSOR=1; shift ;;
    --include-jwt)    INCLUDE_JWT=1; shift ;;
    --no-prompt)      NO_PROMPT=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

# Combine pattern with optional JWT
ACTIVE_PATTERN="$HIGH_CONFIDENCE"
[[ "$INCLUDE_JWT" -eq 1 ]] && ACTIVE_PATTERN="${ACTIVE_PATTERN}|${JWT_PATTERN}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# --- Counters ---
TOTAL_LINES_FOUND=0
TOTAL_FILES_TOUCHED=0
TOTAL_LINES_REMOVED=0

# --- Helpers ---

# Get redacted preview of a string: first 4 + **** + last 4 chars + length.
redact() {
  local s="$1"
  local n=${#s}
  if   (( n <= 8 )); then printf '**** (%d chars)' "$n"
  elif (( n <= 12 )); then printf '%s****%s (%d chars)' "${s:0:2}" "${s: -2}" "$n"
  else                     printf '%s****%s (%d chars)' "${s:0:4}" "${s: -4}" "$n"
  fi
}

# Show colored severity if terminal supports it.
if [[ -t 1 ]]; then
  C_RED=$'\033[1;31m'; C_YELLOW=$'\033[1;33m'; C_GREEN=$'\033[1;32m'
  C_CYAN=$'\033[1;36m'; C_GREY=$'\033[0;37m'; C_RESET=$'\033[0m'
else
  C_RED=""; C_YELLOW=""; C_GREEN=""; C_CYAN=""; C_GREY=""; C_RESET=""
fi

header() { printf '\n%s━━━ %s ━━━%s\n' "$C_CYAN" "$1" "$C_RESET"; }
ok()     { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn()   { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
crit()   { printf '%s⚠%s %s\n' "$C_RED" "$C_RESET" "$1"; }

# Return matching LINE NUMBERS (one per line, sorted unique)
# Uses grep -E (handles {20,} interval expressions correctly, unlike default mawk on Ubuntu).
match_line_numbers() {
  local file="$1"
  [[ -r "$file" ]] || return
  {
    # High-confidence patterns
    grep -nE "$ACTIVE_PATTERN" "$file" 2>/dev/null | cut -d: -f1
    # DB URLs that are NOT local-host
    grep -nE "$DB_URL_PATTERN" "$file" 2>/dev/null \
      | grep -vE "$LOCAL_HOSTS_RE" \
      | cut -d: -f1
  } | sort -un
}

# For dry-run preview: show line numbers + what kind of secret + redacted token.
preview_matches() {
  local file="$1" label="$2"
  [[ -r "$file" ]] || return
  local count
  count=$(match_line_numbers "$file" | wc -l | tr -d ' ')
  if [[ "$count" -eq 0 ]]; then
    ok "$label: 0 matches  ($file)"
    return
  fi
  TOTAL_LINES_FOUND=$((TOTAL_LINES_FOUND + count))
  crit "$label: $count line(s) with real secret(s)  ($file)"

  # Per-line preview using grep + sed (avoids mawk interval-expression issue).
  {
    # HC matches with line numbers
    grep -nE "$ACTIVE_PATTERN" "$file" 2>/dev/null \
      | sed -E 's/^([0-9]+):.*/\1\tkey/' | head -10
    # DB URL matches (non-local) with line numbers
    grep -nE "$DB_URL_PATTERN" "$file" 2>/dev/null \
      | grep -vE "$LOCAL_HOSTS_RE" \
      | sed -E 's/^([0-9]+):.*/\1\tdb-url/' | head -10
  } | sort -un | head -10 | while IFS=$'\t' read -r ln kind; do
    [[ -z "$ln" ]] && continue
    local content
    content=$(sed -n "${ln}p" "$file")
    # Pull the first matching token for redaction
    local token
    if [[ "$kind" == "key" ]]; then
      token=$(printf '%s' "$content" | grep -oE "$ACTIVE_PATTERN" | head -1)
    else
      token=$(printf '%s' "$content" | grep -oE "$DB_URL_PATTERN" | grep -vE "$LOCAL_HOSTS_RE" | head -1)
    fi
    local n=${#token}
    local red
    if   (( n <= 8  )); then red=$(printf '**** (%d chars)' "$n")
    elif (( n <= 12 )); then red=$(printf '%s****%s (%d chars)' "${token:0:2}" "${token: -2}" "$n")
    else                     red=$(printf '%s****%s (%d chars)' "${token:0:4}" "${token: -4}" "$n")
    fi
    printf '    line %5d  [%s]  %s\n' "$ln" "$kind" "$red"
  done
  local extra=$((count - 10))
  if [[ "$extra" -gt 0 ]]; then
    printf "    ... and %d more (truncated for display)\n" "$extra"
  fi
}

# Purge a single text file: remove lines with real secrets, keep the rest.
# Uses sed -i with line-number deletion (avoids mawk interval-expression bug).
purge_file() {
  local file="$1" label="$2"
  [[ -r "$file" && -w "$file" ]] || return
  local lines
  lines=$(match_line_numbers "$file")
  local count
  count=$(printf '%s' "$lines" | grep -c . 2>/dev/null) || count=0
  if [[ "$count" -eq 0 ]]; then
    ok "$label: nothing to remove"
    return
  fi
  local backup="${file}.bak.${TIMESTAMP}"
  cp -p "$file" "$backup"
  # Build a sed expression: <line>d for each line number (descending so deletes don't
  # shift remaining numbers).
  local sed_script
  sed_script=$(printf '%s\n' "$lines" | sort -rn | sed -E 's/$/d/' | tr '\n' ';')
  sed "$sed_script" "$backup" > "$file"
  TOTAL_FILES_TOUCHED=$((TOTAL_FILES_TOUCHED + 1))
  TOTAL_LINES_REMOVED=$((TOTAL_LINES_REMOVED + count))
  ok "$label: removed $count line(s) — backup at $backup"
}

# --- Main ---

if [[ "$MODE" == "dryrun" ]]; then
  printf '%sDRY-RUN%s — no changes will be made. Pass --purge to actually delete.\n' "$C_YELLOW" "$C_RESET"
else
  printf '%sPURGE MODE%s — files will be modified, backups saved as <file>.bak.%s\n' "$C_RED" "$C_RESET" "$TIMESTAMP"
  if [[ "$NO_PROMPT" -eq 0 ]]; then
    read -r -p "Continue? (yes/no) " ans
    [[ "$ans" == "yes" ]] || { echo "Aborted."; exit 1; }
  fi
fi
echo
printf 'Active patterns: HIGH_CONFIDENCE'
[[ "$INCLUDE_JWT" -eq 1 ]] && printf ' + JWT'
printf ' + DB URLs (excluding @local hosts)\n'

# 1. Shell histories
header "Shell histories"
for f in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.psql_history" "$HOME/.mysql_history"; do
  [[ -f "$f" ]] || continue
  if [[ "$MODE" == "dryrun" ]]; then
    preview_matches "$f" "$(basename "$f")"
  else
    purge_file "$f" "$(basename "$f")"
  fi
done

# 2. Claude Code global history
header "Claude Code global history"
CC_HIST="$HOME/.claude/history.jsonl"
if [[ -f "$CC_HIST" ]]; then
  if [[ "$MODE" == "dryrun" ]]; then
    preview_matches "$CC_HIST" "~/.claude/history.jsonl"
  else
    purge_file "$CC_HIST" "~/.claude/history.jsonl"
  fi
else
  ok "~/.claude/history.jsonl not found"
fi

# 3. Claude Code session files
header "Claude Code sessions"
session_files=()
while IFS= read -r f; do
  [[ -n "$f" ]] && session_files+=("$f")
done < <(find "$HOME/.claude/projects" -name '*.jsonl' 2>/dev/null)

if [[ ${#session_files[@]} -eq 0 ]]; then
  ok "no Claude Code session files found"
else
  echo "scanning ${#session_files[@]} session files..."
  if [[ "$MODE" == "dryrun" ]]; then
    leaky=0
    total_lines=0
    for f in "${session_files[@]}"; do
      n=$(match_line_numbers "$f" 2>/dev/null | wc -l | tr -d ' ')
      [[ "$n" -gt 0 ]] && { leaky=$((leaky+1)); total_lines=$((total_lines+n)); }
    done
    if [[ "$leaky" -eq 0 ]]; then
      ok "no real secrets in session files"
    else
      crit "$leaky session file(s) contain a total of $total_lines line(s) with real secrets"
      echo "    (run --purge to remove those lines while keeping the rest of each session)"
      TOTAL_LINES_FOUND=$((TOTAL_LINES_FOUND + total_lines))
    fi
  else
    leaky=0
    for f in "${session_files[@]}"; do
      n=$(match_line_numbers "$f" 2>/dev/null | wc -l | tr -d ' ')
      [[ "$n" -eq 0 ]] && continue
      leaky=$((leaky+1))
      purge_file "$f" "$(basename "$(dirname "$f")")/$(basename "$f")"
    done
    [[ "$leaky" -eq 0 ]] && ok "no session files needed cleaning"
  fi
fi

# 4. Cline state files (api_conversation_history.json, ui_messages.json)
header "Cline state (VS Code extension)"
cline_files=()
for cline_root in "$HOME/.config/Code/User/globalStorage" "$HOME/Library/Application Support/Code/User/globalStorage" "$HOME/.vscode/extensions"; do
  [[ -d "$cline_root" ]] || continue
  while IFS= read -r f; do
    [[ -n "$f" ]] && cline_files+=("$f")
  done < <(find "$cline_root" -path '*cline*' -type f \( -name 'api_conversation_history.json' -o -name 'ui_messages.json' \) 2>/dev/null)
done

if [[ ${#cline_files[@]} -eq 0 ]]; then
  ok "no Cline state files found"
else
  echo "scanning ${#cline_files[@]} Cline state files..."
  if [[ "$MODE" == "dryrun" ]]; then
    leaky=0
    total_lines=0
    for f in "${cline_files[@]}"; do
      n=$(match_line_numbers "$f" 2>/dev/null | wc -l | tr -d ' ')
      [[ "$n" -gt 0 ]] && { leaky=$((leaky+1)); total_lines=$((total_lines+n)); }
    done
    if [[ "$leaky" -eq 0 ]]; then
      ok "no real secrets in Cline state"
    else
      crit "$leaky Cline state file(s) contain a total of $total_lines line(s) with real secrets"
      TOTAL_LINES_FOUND=$((TOTAL_LINES_FOUND + total_lines))
    fi
  else
    leaky=0
    for f in "${cline_files[@]}"; do
      n=$(match_line_numbers "$f" 2>/dev/null | wc -l | tr -d ' ')
      [[ "$n" -eq 0 ]] && continue
      leaky=$((leaky+1))
      purge_file "$f" "Cline/$(basename "$(dirname "$f")")/$(basename "$f")"
    done
    [[ "$leaky" -eq 0 ]] && ok "no Cline files needed cleaning"
  fi
fi

# 5. Cursor SQLite — opt-in nuke
if [[ "$INCLUDE_CURSOR" -eq 1 ]]; then
  header "Cursor SQLite (full wipe)"
  for p in "$HOME/.config/Cursor/User/globalStorage/state.vscdb" "$HOME/Library/Application Support/Cursor/User/globalStorage/state.vscdb"; do
    [[ -f "$p" ]] || continue
    if [[ "$MODE" == "dryrun" ]]; then
      sz=$(du -h "$p" | cut -f1)
      crit "would move: $p ($sz) → $p.purged-$TIMESTAMP"
    else
      mv "$p" "$p.purged-$TIMESTAMP"
      ok "wiped: $p (backup at $p.purged-$TIMESTAMP)"
    fi
  done
  for d in "$HOME/.config/Cursor/User/workspaceStorage" "$HOME/Library/Application Support/Cursor/User/workspaceStorage"; do
    [[ -d "$d" ]] || continue
    if [[ "$MODE" == "dryrun" ]]; then
      sz=$(du -sh "$d" 2>/dev/null | cut -f1)
      crit "would move: $d ($sz) → $d.purged-$TIMESTAMP"
    else
      mv "$d" "$d.purged-$TIMESTAMP"
      ok "wiped: $d (backup at $d.purged-$TIMESTAMP)"
    fi
  done
fi

# --- Summary ---
header "Summary"
if [[ "$MODE" == "dryrun" ]]; then
  printf '%sTotal lines containing real secrets:%s %d\n' "$C_YELLOW" "$C_RESET" "$TOTAL_LINES_FOUND"
  printf 'Re-run with %s--purge%s to remove them. Files will be backed up.\n' "$C_GREEN" "$C_RESET"
else
  printf '%sFiles touched:%s %d\n' "$C_GREEN" "$C_RESET" "$TOTAL_FILES_TOUCHED"
  printf '%sLines removed:%s %d\n' "$C_GREEN" "$C_RESET" "$TOTAL_LINES_REMOVED"
  echo "Backups: $HOME/.../*.bak.$TIMESTAMP (and Cursor *.purged-$TIMESTAMP if --include-cursor)"
  echo "If anything went wrong, restore with: cp <backup> <original>"
  echo
  echo "Recommended: re-run the audit to confirm the secrets-distinct count dropped:"
  echo "  bash $(dirname "$0")/run-audit.sh --no-open"
  echo "  jq -r '\"\\(.score)/100  secrets:\\(.summary.secrets_distinct)\"' ~/.ai-agent-audit/audit-report.json"
fi
