#!/usr/bin/env bash
# Module J: Shell history + AI sessions audit
# Scans for credentials in command history and inside AI tool session storage.
# Each detected match is classified by service (AWS / GitHub / Stripe / Postgres / ...) and
# only a redacted fingerprint (first 4 + last 4 + length) is persisted — never the value.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/secrets.sh"

MODULE="J"
log "$MODULE" "Starting shell history + AI sessions audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# Wrapper: scan a single file, classify into inventory, emit a finding when secrets are found.
scan_file_and_finding() {
  local file="$1" label="$2" severity="$3"
  [[ -r "$file" ]] || return
  local count
  count=$(scan_classify_to_inventory "$file" "$label")
  if [[ "${count:-0}" -gt 0 ]]; then
    emit_finding "$MODULE" "$severity" "J.leak" \
      "$label contains $count classified secret(s) — see secrets-inventory.md" \
      "Path: $file. Each detected secret is classified by service and listed with a redacted fingerprint in the inventory file." \
      "Open the inventory: cat \"$SECRETS_INVENTORY\". For each entry — identify the matching key in your provider UI by fingerprint and rotate it. Then redact the source with scripts/purge-secrets.sh (dry-run first)." \
      "Credentials in history files are read by Nx-style scanners and any agent that walks \$HOME"
  fi
}

# Files under <dir> matching the find predicates, newest first (one path per line).
newest_first() {
  local dir="$1"; shift
  if [[ "$OS" == "macos" ]]; then
    find "$dir" -type f "$@" -exec stat -f '%m %N' {} + 2>/dev/null
  else
    find "$dir" -type f "$@" -printf '%T@ %p\n' 2>/dev/null
  fi | sort -rn | cut -d' ' -f2-
}

# Aggregated secret scan over a directory of transcripts. Scans the newest
# SESSION_CAP files and says so when there were more.
# scan_store <label> <finding-id> <severity> <dir> [find predicates...]
SESSION_CAP=500
scan_store() {
  local label="$1" id="$2" sev="$3" dir="$4"; shift 4
  [[ -d "$dir" ]] || return 0
  local all=() f
  while IFS= read -r f; do [[ -n "$f" ]] && all+=("$f"); done < <(newest_first "$dir" "$@")
  [[ "${#all[@]}" -eq 0 ]] && return 0
  local scan=("${all[@]:0:$SESSION_CAP}")
  if [[ "${#all[@]}" -gt "$SESSION_CAP" ]]; then
    emit_finding "$MODULE" "INFO" "$id.capped" \
      "$label: scanned the newest ${#scan[@]} of ${#all[@]} files" \
      "Older files in $dir were not checked for secrets." \
      "Delete transcripts you no longer need, or grep the rest yourself: grep -lE '<pattern>' -r \"$dir\"." ""
  fi
  local cnt leaky
  read -r cnt leaky < <(scan_classify_files_aggregated "$label" "Newest ${#scan[@]} of ${#all[@]} file(s) under $dir." "${scan[@]}")
  [[ "${cnt:-0}" -gt 0 ]] || return 0
  emit_finding "$MODULE" "$sev" "$id" \
    "$label: $leaky file(s) contain $cnt distinct classified secret(s)" \
    "Under $dir. Plaintext, readable by any process running as this user — including the next agent session. See $SECRETS_INVENTORY for the classified list." \
    "Rotate each classified credential first. Then redact them in place with scripts/purge-secrets.sh (dry-run by default, --purge to apply). Stop pasting secrets into chat — use env vars or vault references." \
    "Agent context windows are persistent, not ephemeral"
}

# ---------- J.1: Shell histories ----------
scan_file_and_finding "$HOME/.bash_history"        "Bash history"          "HIGH"
scan_file_and_finding "$HOME/.zsh_history"         "Zsh history"           "HIGH"
scan_file_and_finding "$HOME/.psql_history"        "psql history"          "HIGH"
scan_file_and_finding "$HOME/.mysql_history"       "mysql history"         "HIGH"
scan_file_and_finding "$HOME/.node_repl_history"   "Node REPL history"     "MEDIUM"
scan_file_and_finding "$HOME/.python_history"      "Python REPL history"   "MEDIUM"
scan_file_and_finding "$HOME/.sqlite_history"      "SQLite history"        "MEDIUM"
scan_file_and_finding "$HOME/.lesshst"             "less history"          "LOW"

# Fish shell history (different format but grep still works on the value lines)
[[ -f "$HOME/.local/share/fish/fish_history" ]] && \
  scan_file_and_finding "$HOME/.local/share/fish/fish_history" "Fish history" "HIGH"

# Atuin sync DB (newer history-sync tool, SQLite under ~/.local/share/atuin/history.db)
if [[ "$HAS_SQLITE" -eq 1 && -f "$HOME/.local/share/atuin/history.db" ]]; then
  count=$(sqlite3 "$HOME/.local/share/atuin/history.db" "SELECT command FROM history LIMIT 5000;" 2>/dev/null \
    | scan_classify_stdin_to_inventory "Atuin history (SQLite)")
  if [[ "${count:-0}" -gt 0 ]]; then
    emit_finding "$MODULE" "HIGH" "J.atuin" \
      "Atuin history DB contains $count classified secret(s)" \
      "Path: $HOME/.local/share/atuin/history.db. Atuin syncs history across machines — secrets here may be replicated remotely." \
      "Inspect classified entries in $SECRETS_INVENTORY. Rotate exposed credentials. Consider atuin's --secret filter or per-command suppression." \
      ""
  fi
fi

# ---------- J.2: Claude Code sessions ----------
CC_DIR="$HOME/.claude"
if [[ -d "$CC_DIR" ]]; then
  # Global config presence (informational)
  if [[ -f "$CC_DIR.json" ]]; then
    perms=$(file_perm_octal "$CC_DIR.json")
    emit_finding "$MODULE" "INFO" "J.2.cc.global" "Claude Code global config: ~/.claude.json (perms $perms)" "" "" ""
  fi

  # Session inventory + aggregated secret scan across last 90 days.
  if [[ -d "$CC_DIR/projects" ]]; then
    session_count=$(find "$CC_DIR/projects" -name '*.jsonl' 2>/dev/null | wc -l | tr -d ' ')
    emit_finding "$MODULE" "INFO" "J.2.cc.count" \
      "$session_count Claude Code session file(s) on disk" \
      "Stored at $CC_DIR/projects/<encoded-project-path>/<session-id>.jsonl. Plaintext, readable by any process running as this user." "" ""

    # Secrets in sessions from the last 90 days, newest first.
    scan_store "Claude Code sessions (last 90d)" "J.2.cc.leak" "HIGH" "$CC_DIR/projects" -name '*.jsonl' -mtime -90
  fi

  # Snapshots of files Claude Code edited (.env contents end up here) and shell snapshots.
  scan_store "Claude Code file-history snapshots" "J.2.cc.filehist" "HIGH" "$CC_DIR/file-history"
  scan_store "Claude Code shell snapshots" "J.2.cc.snapshots" "MEDIUM" "$CC_DIR/shell-snapshots"

  # Global prompt history file
  if [[ -f "$CC_DIR/history.jsonl" ]]; then
    h_count=$(scan_classify_to_inventory "$CC_DIR/history.jsonl" "Claude Code global history (~/.claude/history.jsonl)")
    if [[ "${h_count:-0}" -gt 0 ]]; then
      emit_finding "$MODULE" "HIGH" "J.2.cc.histleak" \
        "~/.claude/history.jsonl (global prompts) contains $h_count classified secret(s)" \
        "Single global file across all Claude Code projects. See $SECRETS_INVENTORY for service-by-service breakdown." \
        "Rotate each classified credential, then truncate or delete: rm ~/.claude/history.jsonl. Fix the workflow that put secrets in prompts." ""
    fi
  fi
fi

# ---------- J.3: Cursor SQLite chat history ----------
CURSOR_STATE=()
[[ "$OS" == "macos" ]] && CURSOR_STATE+=("$HOME/Library/Application Support/Cursor/User/globalStorage/state.vscdb")
[[ "$OS" == "linux" ]] && CURSOR_STATE+=("$HOME/.config/Cursor/User/globalStorage/state.vscdb")

if [[ "$OS" == "macos" ]]; then
  WS_DIR="$HOME/Library/Application Support/Cursor/User/workspaceStorage"
else
  WS_DIR="$HOME/.config/Cursor/User/workspaceStorage"
fi

for db in "${CURSOR_STATE[@]}"; do
  [[ -f "$db" ]] || continue
  emit_finding "$MODULE" "INFO" "J.3.cursor.db" \
    "Cursor global state DB present: $db" \
    "Stores chat history (composerData, aiService.prompts) in SQLite cursorDiskKV table." "" ""

  if [[ "$HAS_SQLITE" -eq 1 ]]; then
    cnt=$(sqlite3 "$db" "SELECT value FROM cursorDiskKV WHERE [key] LIKE 'composerData:%' OR [key] LIKE 'bubbleId:%' LIMIT 2000;" 2>/dev/null \
      | scan_classify_stdin_to_inventory "Cursor global chat history")
    if [[ "${cnt:-0}" -gt 0 ]]; then
      emit_finding "$MODULE" "HIGH" "J.3.cursor.leak" \
        "Cursor chat history contains $cnt classified secret(s) — see secrets-inventory.md" \
        "Cursor chat content stored in SQLite cursorDiskKV table." \
        "Inspect manually: sqlite3 \"$db\" \"SELECT key,length(value) FROM cursorDiskKV;\". Rotate classified credentials. Delete affected sessions, or wipe the whole DB if history is dispensable. Stop pasting secrets in Cursor chat." \
        ""
    fi
  fi
done

# Workspace storage (per-project)
if [[ -d "$WS_DIR" ]]; then
  ws_count=$(ls -1 "$WS_DIR" 2>/dev/null | wc -l | tr -d ' ')
  emit_finding "$MODULE" "INFO" "J.3.cursor.ws" "Cursor has $ws_count workspace storage entries (per-project chat)" "" "" ""

  if [[ "$HAS_SQLITE" -eq 1 ]]; then
    leaky_ws=0
    total_ws_secrets=0
    while IFS= read -r dbf; do
      [[ -z "$dbf" ]] && continue
      cnt=$(sqlite3 "$dbf" "SELECT value FROM ItemTable WHERE key IN ('aiService.prompts','workbench.panel.aichat.view.aichat.chatdata');" 2>/dev/null \
        | scan_classify_stdin_to_inventory "Cursor workspace chat ($(basename "$(dirname "$dbf")"))")
      if [[ "${cnt:-0}" -gt 0 ]]; then
        leaky_ws=$((leaky_ws+1))
        total_ws_secrets=$((total_ws_secrets+cnt))
      fi
    done < <(find "$WS_DIR" -name 'state.vscdb' 2>/dev/null | head -50)

    if [[ "$leaky_ws" -gt 0 ]]; then
      emit_finding "$MODULE" "HIGH" "J.3.cursor.wsleak" \
        "$leaky_ws Cursor workspace state file(s) contain $total_ws_secrets classified secret(s) in chat history" \
        "Per-project chat persists secrets even after you 'delete' chats in UI. See $SECRETS_INVENTORY for per-workspace breakdown." \
        "Wipe affected workspace storage entries. Future workflow: never paste credentials into Cursor chat — use file references with env vars instead." \
        ""
    fi
  fi
fi

# ---------- J.4: Other AI tool session storage ----------
# Aider
scan_file_and_finding "$HOME/.aider.input.history"   "Aider input history" "HIGH"
scan_file_and_finding "$HOME/.aider.chat.history.md" "Aider chat history"  "HIGH"

# Codex CLI
scan_file_and_finding "$HOME/.codex/history.jsonl" "Codex prompt history" "HIGH"
scan_store "Codex sessions" "J.4.codex" "HIGH" "$HOME/.codex/sessions" -name '*.jsonl'

# Gemini CLI chat checkpoints
scan_store "Gemini CLI chats" "J.4.gemini" "HIGH" "$HOME/.gemini/tmp" -path '*/chats/*'

# Cline (VS Code extension id saoudrizwan.claude-dev) task transcripts, in VS Code,
# VS Code Insiders and Cursor, on Linux and macOS.
for gs in "$HOME/.config/Code/User/globalStorage" \
          "$HOME/.config/Code - Insiders/User/globalStorage" \
          "$HOME/.config/Cursor/User/globalStorage" \
          "$HOME/Library/Application Support/Code/User/globalStorage" \
          "$HOME/Library/Application Support/Code - Insiders/User/globalStorage" \
          "$HOME/Library/Application Support/Cursor/User/globalStorage"; do
  scan_store "Cline tasks ($gs)" "J.4.cline" "MEDIUM" "$gs/saoudrizwan.claude-dev/tasks" \
    \( -name 'api_conversation_history.json' -o -name 'ui_messages.json' \)
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
