#!/usr/bin/env bash
# purge-secrets.sh — find credentials in local history files and AI session storage and
# redact them in place.
#
# Default behaviour: DRY-RUN (only reports). Pass --purge to modify files.
#
# --purge replaces each detected secret with [REDACTED:<fingerprint>]. Line count and JSONL
# structure are preserved, so Claude Code sessions stay resumable (deleting lines would
# break their parentUuid chain). --delete-lines removes whole matching lines instead.
#
# Sources scanned:
#   - ~/.bash_history, ~/.zsh_history, ~/.psql_history, ~/.mysql_history, fish history
#   - ~/.claude/history.jsonl
#   - ~/.claude/projects/<encoded-project-path>/*.jsonl   (Claude Code sessions)
#   - ~/.claude/file-history/**                           (snapshots of edited files)
#   - ~/.codex/history.jsonl, ~/.codex/sessions/**/*.jsonl
#   - Cline task state (api_conversation_history.json, ui_messages.json)
#   - Cursor state.vscdb + workspaceStorage/              (only with --include-cursor; moved, not edited)
#
# Detection uses the HIGH/CRITICAL patterns of lib/secrets.sh, the same set the audit uses.
#   - DB connection strings with an embedded password are purged only if the host is not
#     local (localhost, 127.x, 0.0.0.0, ::1, host.docker.internal, db, postgres, ...).
#   - JWTs are skipped by default (high false-positive rate); --include-jwt adds them.
#   - Raw PEM private keys are not purged: a key spans many lines in history files, and in
#     JSONL a greedy BEGIN…END match could cut across JSON fields. The audit still reports them.
#
# Backups: before a file is modified it is copied to
#   $AUDIT_DIR/purge-backups/<TIMESTAMP>/   (directory 700, files 600)
# The backups contain the original secrets — delete them once you have verified the result.
# --no-backup skips them.
#
# Close running agent sessions (Claude Code, Codex, Cursor) before --purge: a session that
# appends to its JSONL while it is being rewritten can lose those lines.

set -u
# bash >= 4.4: associative arrays, mapfile, and empty "${arr[@]}" under set -u (an
# "unbound variable" error before 4.4). Stock macOS /bin/bash is 3.2.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  printf 'ai-agent-audit needs bash >= 4.4 (found %s).\n' "$BASH_VERSION" >&2
  printf 'macOS: brew install bash, then run: "$(brew --prefix)/bin/bash" %s\n' "$0" >&2
  exit 2
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_DIR="${AUDIT_DIR:-$HOME/.ai-agent-audit}"
export AUDIT_DIR
umask 077
# shellcheck source=lib/secrets.sh
source "$SCRIPT_DIR/lib/secrets.sh"

# --- Args ---
MODE="dryrun"
DELETE_LINES=0
NO_BACKUP=0
INCLUDE_CURSOR=0
INCLUDE_JWT=0
NO_PROMPT=0

usage() {
  cat <<EOF
Usage: $0 [--purge] [--delete-lines] [--no-backup] [--include-cursor] [--include-jwt] [--no-prompt]

  --purge            Modify files. Without this, runs a dry-run and changes nothing.
  --delete-lines     With --purge: delete every line holding a secret instead of redacting
                     the secret in place. Breaks Claude Code session resume; prefer the default.
  --no-backup        Do not keep copies of the original files (they contain the secrets).
  --include-cursor   Also move Cursor's state.vscdb and workspaceStorage/ out of the way
                     (into the backup directory, or deleted with --no-backup).
  --include-jwt      Also treat JWTs (eyJ...) as secrets. Default: skipped (high FP rate).
  --no-prompt        Skip the confirmation prompt in --purge mode.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)          MODE="purge"; shift ;;
    --delete-lines)   DELETE_LINES=1; shift ;;
    --no-backup)      NO_BACKUP=1; shift ;;
    --include-cursor) INCLUDE_CURSOR=1; shift ;;
    --include-jwt)    INCLUDE_JWT=1; shift ;;
    --no-prompt)      NO_PROMPT=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

# --- Patterns ---
# Password part excludes quotes and backslashes so a match can never extend past the end
# of a JSON string value.
DB_URL_PATTERN='(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqps?)://[A-Za-z0-9._%+-]+:[^@[:space:]"'"'"'\\]+@[A-Za-z0-9._-]+'
LOCAL_HOSTS_RE='@(localhost|127\.0\.0\.[0-9]+|0\.0\.0\.0|::1|host\.docker\.internal|db|postgres|mysql|mongo|redis|host)([:/]|$)'

build_purge_pattern() {
  local pats=() entry pat rest type_label sev
  for entry in "${SECRET_PATTERNS[@]}"; do
    pat="${entry%%|||*}"; rest="${entry#*|||}"
    type_label="${rest%%|||*}"
    sev="${entry##*|||}"
    case "$pat" in
      postgres*|mysql*|mongodb*|redis*|amqp*|*PRIVATE*) continue ;;   # handled above / not purged
    esac
    if [[ "$type_label" == JWT* ]]; then
      [[ "$INCLUDE_JWT" -eq 1 ]] || continue
    elif [[ "$sev" != "HIGH" && "$sev" != "CRITICAL" ]]; then
      continue
    fi
    pats+=("$pat")
  done
  bounded_pattern "${pats[@]}"
}
# Bounded like the audit (see SECRET_LEFT in lib/secrets.sh): purging an unbounded match
# would rewrite random fragments of base64 blobs, e.g. Codex's encrypted reasoning.
ACTIVE_PATTERN=$(build_purge_pattern)
DB_URL_BOUNDED=$(bounded_pattern "$DB_URL_PATTERN")

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$AUDIT_DIR/purge-backups/$TIMESTAMP"

# --- Counters ---
TOTAL_LINES_FOUND=0
TOTAL_FILES_TOUCHED=0
TOTAL_SECRETS_REDACTED=0
TOTAL_LINES_REMOVED=0
FILES_WITH_SECRETS=0

# --- Output helpers ---
if [[ -t 1 ]]; then
  C_RED=$'\033[1;31m'; C_YELLOW=$'\033[1;33m'; C_GREEN=$'\033[1;32m'
  C_CYAN=$'\033[1;36m'; C_RESET=$'\033[0m'
else
  C_RED=""; C_YELLOW=""; C_GREEN=""; C_CYAN=""; C_RESET=""
fi

header() { printf '\n%s━━━ %s ━━━%s\n' "$C_CYAN" "$1" "$C_RESET"; }
ok()     { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
crit()   { printf '%s⚠%s %s\n' "$C_RED" "$C_RESET" "$1"; }

# --- Detection ---

# Unique secret values in a file, one per line (stays inside this process).
file_secrets() {
  local file="$1"
  [[ -r "$file" ]] || return
  {
    grep -oE -e "$ACTIVE_PATTERN" "$file"
    grep -oE -e "$DB_URL_BOUNDED" "$file" | grep -vE "$LOCAL_HOSTS_RE"
  } 2>/dev/null | strip_left | sort -u
}

# Numbers of the lines that hold any of the given secrets (fixed-string match).
lines_with() {  # lines_with <file> <secrets-file>
  grep -nF -f "$2" "$1" 2>/dev/null | cut -d: -f1 | sort -un
}

label_for() {  # human label for one secret value
  case "$1" in
    postgres*|mysql*|mongodb*|redis*|amqp*) printf 'DB URL with password' ;;
    *) local c; c=$(classify_secret_match "$1"); printf '%s' "${c%%|||*}" ;;
  esac
}

# --- Actions ---

backup_file() {
  [[ "$NO_BACKUP" -eq 1 ]] && return 0
  mkdir -p "$BACKUP_DIR"
  local dest="$BACKUP_DIR/${1//\//__}"
  cp -p "$1" "$dest" && chmod 600 "$dest"
}

# Replace each secret literally with [REDACTED:<fingerprint>]. awk index/substr instead of
# sed: secrets contain characters that are special in sed patterns and replacements.
redact_in_place() {  # redact_in_place <file> <secrets-file>
  local file="$1" secrets="$2" pairs out s
  pairs=$(_secrets_mktemp); out=$(_secrets_mktemp)
  # Longest first, so a secret that contains another is replaced whole.
  while IFS= read -r s; do
    printf '%d\t%s\t[REDACTED:%s]\n' "${#s}" "$s" "$(redact_fingerprint "$s")"
  done < "$secrets" | sort -t$'\t' -k1,1 -rn | cut -f2- > "$pairs"
  LC_ALL=C awk -F'\t' '
    function rep(s, from, to,   o, i) {
      o = ""
      while ((i = index(s, from)) > 0) { o = o substr(s, 1, i - 1) to; s = substr(s, i + length(from)) }
      return o s
    }
    NR == FNR { from[++n] = $1; to[n] = $2; next }
    { line = $0; for (k = 1; k <= n; k++) line = rep(line, from[k], to[k]); print line }
  ' "$pairs" "$file" > "$out" || return 1
  # Write through the original inode (keeps permissions, ownership, hard links), with
  # INT/TERM ignored so a Ctrl-C cannot leave the file half-written.
  (trap '' INT TERM; cat "$out" > "$file")
}

delete_lines() {  # delete_lines <file> <line-numbers-file>
  local file="$1" lines="$2" out
  out=$(_secrets_mktemp)
  LC_ALL=C awk 'NR == FNR { del[$1] = 1; next } !(FNR in del)' "$lines" "$file" > "$out" || return 1
  (trap '' INT TERM; cat "$out" > "$file")
}

# Process one file: dry-run preview or purge.
process_file() {
  local file="$1" label="$2"
  [[ -r "$file" ]] || return 0
  local secrets lines n_secrets n_lines
  secrets=$(_secrets_mktemp); lines=$(_secrets_mktemp)
  file_secrets "$file" > "$secrets"
  n_secrets=$(grep -c . "$secrets")
  [[ "$n_secrets" -eq 0 ]] && return 0
  lines_with "$file" "$secrets" > "$lines"
  n_lines=$(grep -c . "$lines")
  TOTAL_LINES_FOUND=$((TOTAL_LINES_FOUND + n_lines))
  FILES_WITH_SECRETS=$((FILES_WITH_SECRETS + 1))

  if [[ "$MODE" == "dryrun" ]]; then
    [[ "$FILES_WITH_SECRETS" -gt 20 ]] && return 0
    crit "$label: $n_secrets secret(s) on $n_lines line(s)  ($file)"
    local s shown=0
    while IFS= read -r s; do
      shown=$((shown + 1))
      if [[ "$shown" -gt 5 ]]; then printf '    ... and %d more\n' $((n_secrets - 5)); break; fi
      printf '    %-34s %s\n' "$(label_for "$s")" "$(redact_fingerprint "$s")"
    done < "$secrets"
    return 0
  fi

  if [[ ! -w "$file" ]]; then
    crit "$label: not writable, skipped ($file)"
    return 0
  fi
  backup_file "$file" || { crit "$label: backup failed, file left untouched ($file)"; return 0; }
  if [[ "$DELETE_LINES" -eq 1 ]]; then
    delete_lines "$file" "$lines" || { crit "$label: rewrite failed ($file)"; return 0; }
    TOTAL_LINES_REMOVED=$((TOTAL_LINES_REMOVED + n_lines))
    ok "$label: removed $n_lines line(s)  ($file)"
  else
    redact_in_place "$file" "$secrets" || { crit "$label: rewrite failed ($file)"; return 0; }
    TOTAL_SECRETS_REDACTED=$((TOTAL_SECRETS_REDACTED + n_secrets))
    ok "$label: redacted $n_secrets secret(s) on $n_lines line(s)  ($file)"
  fi
  TOTAL_FILES_TOUCHED=$((TOTAL_FILES_TOUCHED + 1))
}

# Process a group of files under one heading.
process_group() {
  local title="$1"; shift
  header "$title"
  FILES_WITH_SECRETS=0
  local f n=0
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    n=$((n + 1))
    process_file "$f" "$(basename "$f")"
  done
  if [[ "$n" -eq 0 ]]; then
    ok "nothing to scan"
  elif [[ "$FILES_WITH_SECRETS" -eq 0 ]]; then
    ok "$n file(s) scanned, no secrets"
  elif [[ "$MODE" == "dryrun" && "$FILES_WITH_SECRETS" -gt 20 ]]; then
    printf '    ... %d more file(s) with secrets (listing capped at 20)\n' $((FILES_WITH_SECRETS - 20))
  fi
}

# find_files <dir> [find predicates...] — NUL-safe, results in the FOUND array.
find_files() {
  FOUND=()
  local d="$1"; shift
  [[ -d "$d" ]] || return 0
  local f
  while IFS= read -r -d '' f; do FOUND+=("$f"); done < <(find "$d" -type f "$@" -print0 2>/dev/null)
}

# --- Main ---

if [[ "$MODE" == "dryrun" ]]; then
  printf '%sDRY-RUN%s — no changes will be made. Pass --purge to redact.\n' "$C_YELLOW" "$C_RESET"
else
  if [[ "$DELETE_LINES" -eq 1 ]]; then
    printf '%sPURGE MODE (delete lines)%s — matching lines will be removed.\n' "$C_RED" "$C_RESET"
  else
    printf '%sPURGE MODE%s — secrets will be replaced with [REDACTED:<fingerprint>].\n' "$C_RED" "$C_RESET"
  fi
  if [[ "$NO_BACKUP" -eq 1 ]]; then
    echo "No backups will be kept."
  else
    echo "Originals are copied to $BACKUP_DIR first."
  fi
  echo "Close running Claude Code / Codex / Cursor sessions before continuing."
  if [[ "$NO_PROMPT" -eq 0 ]]; then
    read -r -p "Continue? (yes/no) " ans
    [[ "$ans" == "yes" ]] || { echo "Aborted."; exit 1; }
  fi
fi
echo
printf 'Active patterns: HIGH/CRITICAL from lib/secrets.sh'
[[ "$INCLUDE_JWT" -eq 1 ]] && printf ' + JWT'
printf ' + DB URLs (excluding local hosts)\n'

process_group "Shell histories" \
  "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.psql_history" "$HOME/.mysql_history" \
  "$HOME/.local/share/fish/fish_history"

process_group "Claude Code global history" "$HOME/.claude/history.jsonl"

find_files "$HOME/.claude/projects" -name '*.jsonl'
process_group "Claude Code sessions (~/.claude/projects/*/*.jsonl)" "${FOUND[@]}"

find_files "$HOME/.claude/file-history"
process_group "Claude Code file-history snapshots" "${FOUND[@]}"

find_files "$HOME/.codex/sessions" -name '*.jsonl'
process_group "Codex history and sessions" "$HOME/.codex/history.jsonl" "${FOUND[@]}"

cline_files=()
for cline_root in "$HOME/.config/Code/User/globalStorage" "$HOME/Library/Application Support/Code/User/globalStorage"; do
  find_files "$cline_root" -path '*saoudrizwan.claude-dev*' \( -name 'api_conversation_history.json' -o -name 'ui_messages.json' \)
  cline_files+=("${FOUND[@]}")
done
process_group "Cline task state" "${cline_files[@]}"

# Cursor stores chat in SQLite; editing it in place is unsafe, so it is moved aside whole.
if [[ "$INCLUDE_CURSOR" -eq 1 ]]; then
  header "Cursor SQLite (moved aside whole)"
  for p in "$HOME/.config/Cursor/User/globalStorage/state.vscdb" \
           "$HOME/Library/Application Support/Cursor/User/globalStorage/state.vscdb" \
           "$HOME/.config/Cursor/User/workspaceStorage" \
           "$HOME/Library/Application Support/Cursor/User/workspaceStorage"; do
    [[ -e "$p" ]] || continue
    if [[ "$MODE" == "dryrun" ]]; then
      crit "would move aside: $p ($(du -sh "$p" 2>/dev/null | cut -f1))"
    elif [[ "$NO_BACKUP" -eq 1 ]]; then
      rm -rf "$p" && ok "deleted: $p"
    else
      mkdir -p "$BACKUP_DIR"
      mv "$p" "$BACKUP_DIR/${p//\//__}" && ok "moved: $p → $BACKUP_DIR"
    fi
  done
fi

# --- Summary ---
header "Summary"
if [[ "$MODE" == "dryrun" ]]; then
  printf '%sLines containing secrets:%s %d\n' "$C_YELLOW" "$C_RESET" "$TOTAL_LINES_FOUND"
  printf 'Rotate the keys in your provider UIs first, then re-run with %s--purge%s.\n' "$C_GREEN" "$C_RESET"
else
  printf '%sFiles modified:%s %d\n' "$C_GREEN" "$C_RESET" "$TOTAL_FILES_TOUCHED"
  if [[ "$DELETE_LINES" -eq 1 ]]; then
    printf '%sLines removed:%s %d\n' "$C_GREEN" "$C_RESET" "$TOTAL_LINES_REMOVED"
  else
    printf '%sSecrets redacted:%s %d\n' "$C_GREEN" "$C_RESET" "$TOTAL_SECRETS_REDACTED"
  fi
  if [[ "$NO_BACKUP" -eq 0 && -d "$BACKUP_DIR" ]]; then
    echo
    printf '%sBackups contain the original secrets.%s After verifying, delete them:\n' "$C_RED" "$C_RESET"
    echo "  rm -rf \"$BACKUP_DIR\""
  fi
  echo
  echo "Recommended: re-run the audit to confirm the secrets count dropped:"
  echo "  bash $SCRIPT_DIR/run-audit.sh --no-open"
fi
