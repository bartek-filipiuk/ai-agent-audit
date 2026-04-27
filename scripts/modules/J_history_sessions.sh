#!/usr/bin/env bash
# Module J: Shell history + AI sessions audit
# Scans for credentials in command history and inside AI tool session storage.
# Uses pattern-only matching — never displays actual secret values.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="J"
log "$MODULE" "Starting shell history + AI sessions audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# Patterns for likely secrets (matches but never reports the matched string)
SECRET_PATTERNS=(
  'AKIA[0-9A-Z]{16}'                                 # AWS Access Key
  'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}'   # AWS Secret
  'ghp_[A-Za-z0-9]{30,}'                             # GitHub classic PAT (varies in length)
  'github_pat_[A-Za-z0-9_]{60,}'                     # GitHub fine-grained
  'gho_[A-Za-z0-9]{30,}'                             # GitHub OAuth
  'ghs_[A-Za-z0-9]{30,}'                             # GitHub server token
  'glpat-[A-Za-z0-9_-]{20}'                          # GitLab PAT
  'sk-(ant|proj|live|test)-[A-Za-z0-9_-]{20,}'       # Anthropic / OpenAI / Stripe
  'xox[baprs]-[A-Za-z0-9-]{10,}'                     # Slack tokens
  'AIza[0-9A-Za-z_-]{35}'                            # Google API
  'ya29\.[0-9A-Za-z_-]+'                             # Google OAuth
  'npm_[A-Za-z0-9]{36}'                              # npm token
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'               # raw private key
  'mysql://[^:]+:[^@]+@'                             # mysql with password
  'postgres(ql)?://[^:]+:[^@]+@'                     # postgres with password
  'mongodb(\+srv)?://[^:]+:[^@]+@'                   # mongodb with password
  'redis://[^:]+:[^@]+@'                             # redis with password
)

# Combine into single grep pattern
GREP_PATTERN="$(IFS='|'; echo "${SECRET_PATTERNS[*]}")"

scan_file_for_secrets() {
  local file="$1" label="$2" severity="$3"
  [[ -r "$file" ]] || return
  # Count matches per pattern; report only counts and pattern types, never matched text
  local total
  total=$(grep -ocE "$GREP_PATTERN" "$file" 2>/dev/null || echo 0)
  if [[ "$total" -gt 0 ]]; then
    # Identify which pattern types matched (without echoing values)
    local types=""
    grep -oE 'AKIA[0-9A-Z]{16}' "$file" >/dev/null 2>&1 && types="$types AWS"
    grep -oE 'ghp_[A-Za-z0-9]{30,}' "$file" >/dev/null 2>&1 && types="$types GitHub-PAT"
    grep -oE 'github_pat_[A-Za-z0-9_]{60,}' "$file" >/dev/null 2>&1 && types="$types GitHub-FG"
    grep -oE 'sk-(ant|proj|live|test)-[A-Za-z0-9_-]{20,}' "$file" >/dev/null 2>&1 && types="$types AI/Stripe-key"
    grep -oE 'xox[baprs]-' "$file" >/dev/null 2>&1 && types="$types Slack"
    grep -oE 'BEGIN .*PRIVATE KEY' "$file" >/dev/null 2>&1 && types="$types PrivateKey"
    grep -oE '(mysql|postgres|mongodb|redis)' "$file" >/dev/null 2>&1 && grep -qE '://[^:]+:[^@]+@' "$file" 2>/dev/null && types="$types DB-URL-with-password"

    emit_finding "$MODULE" "$severity" "J.leak" \
      "$label contains likely secret(s) [count: $total, types:$types]" \
      "Path: $file. Specific values not displayed — audit yourself with: grep -nE 'AKIA|ghp_|sk-|xox' '$file'" \
      "Rotate any matching credentials NOW (assume compromise). Move secrets to a manager. Clear file: history -c && history -w (zsh: history -p)." \
      "Standard threat — credentials in history are read by Nx-style scanners and any agent reading \$HOME"
  fi
}

# ---------- J.1: Shell histories ----------
[[ -f "$HOME/.bash_history" ]] && scan_file_for_secrets "$HOME/.bash_history" "Bash history" "HIGH"
[[ -f "$HOME/.zsh_history" ]] && scan_file_for_secrets "$HOME/.zsh_history" "Zsh history" "HIGH"
[[ -f "$HOME/.psql_history" ]] && scan_file_for_secrets "$HOME/.psql_history" "psql history" "HIGH"
[[ -f "$HOME/.mysql_history" ]] && scan_file_for_secrets "$HOME/.mysql_history" "mysql history" "HIGH"
[[ -f "$HOME/.node_repl_history" ]] && scan_file_for_secrets "$HOME/.node_repl_history" "Node REPL history" "MEDIUM"
[[ -f "$HOME/.python_history" ]] && scan_file_for_secrets "$HOME/.python_history" "Python REPL history" "MEDIUM"

# ---------- J.2: Claude Code sessions ----------
CC_DIR="$HOME/.claude"
if [[ -d "$CC_DIR" ]]; then
  # Global config
  if [[ -f "$CC_DIR.json" ]]; then
    perms=$(file_perm_octal "$CC_DIR.json")
    emit_finding "$MODULE" "INFO" "J.2.cc.global" "Claude Code global config: ~/.claude.json (perms $perms)" "" "" ""
  fi

  # Sessions directory
  if [[ -d "$CC_DIR/projects" ]]; then
    session_count=$(find "$CC_DIR/projects" -name '*.jsonl' 2>/dev/null | wc -l | tr -d ' ')
    emit_finding "$MODULE" "INFO" "J.2.cc.count" \
      "$session_count Claude Code session file(s) on disk" \
      "Stored at $CC_DIR/projects/<project-hash>/sessions/. JSONL format, plaintext readable by any process." "" ""

    # Scan recent sessions for secrets
    leaky=0
    while IFS= read -r jsonl; do
      [[ -z "$jsonl" ]] && continue
      if grep -qE "$GREP_PATTERN" "$jsonl" 2>/dev/null; then
        leaky=$((leaky+1))
        # Don't report each file — just count
      fi
    done < <(find "$CC_DIR/projects" -name '*.jsonl' -mtime -90 2>/dev/null | head -200)

    if [[ "$leaky" -gt 0 ]]; then
      emit_finding "$MODULE" "HIGH" "J.2.cc.leak" \
        "$leaky Claude Code session file(s) (last 90d) contain likely secrets" \
        "Sessions persist plaintext. Anyone reading \$HOME (including future agent runs that re-load context) sees them." \
        "Inspect with: grep -lE 'AKIA|ghp_|sk-' ~/.claude/projects/*/sessions/*.jsonl. Delete sessions with secrets: rm <file>. Stop pasting secrets into chat — use env vars or vault references." \
        "General class — agent context windows are persistent, not ephemeral"
    fi
  fi

  # history.jsonl (global prompt history)
  if [[ -f "$CC_DIR/history.jsonl" ]]; then
    if grep -qE "$GREP_PATTERN" "$CC_DIR/history.jsonl" 2>/dev/null; then
      emit_finding "$MODULE" "HIGH" "J.2.cc.histleak" \
        "~/.claude/history.jsonl (global prompts) contains likely secrets" \
        "" "Truncate or delete: rm ~/.claude/history.jsonl. Fix the workflow that put secrets in prompts." ""
    fi
  fi
fi

# ---------- J.3: Cursor SQLite chat history ----------
CURSOR_STATE=()
[[ "$OS" == "macos" ]] && CURSOR_STATE+=("$HOME/Library/Application Support/Cursor/User/globalStorage/state.vscdb")
[[ "$OS" == "linux" ]] && CURSOR_STATE+=("$HOME/.config/Cursor/User/globalStorage/state.vscdb")

# Workspace storage (per-project)
[[ "$OS" == "macos" ]] && WS_DIR="$HOME/Library/Application Support/Cursor/User/workspaceStorage" || WS_DIR="$HOME/.config/Cursor/User/workspaceStorage"

for db in "${CURSOR_STATE[@]}"; do
  [[ -f "$db" ]] || continue
  emit_finding "$MODULE" "INFO" "J.3.cursor.db" \
    "Cursor global state DB present: $db" \
    "Stores chat history (composerData, aiService.prompts) in SQLite." "" ""

  if [[ "$HAS_SQLITE" -eq 1 ]]; then
    # Pull text out of cursorDiskKV — careful, can be huge. Cap output.
    leak_count=$(sqlite3 "$db" "SELECT value FROM cursorDiskKV WHERE [key] LIKE 'composerData:%' OR [key] LIKE 'bubbleId:%' LIMIT 500;" 2>/dev/null \
      | grep -cE "$GREP_PATTERN" 2>/dev/null || echo 0)
    if [[ "$leak_count" -gt 0 ]]; then
      emit_finding "$MODULE" "HIGH" "J.3.cursor.leak" \
        "Cursor chat history contains likely secrets [matches: $leak_count]" \
        "Cursor chat content stored in SQLite cursorDiskKV table. Inspect manually: sqlite3 '$db' \"SELECT value FROM cursorDiskKV WHERE value LIKE '%AKIA%' OR value LIKE '%ghp_%';\"" \
        "Delete the affected sessions, or wipe the whole DB if you don't need history. Stop pasting secrets in Cursor chat." \
        ""
    fi
  fi
done

# Workspace state files
if [[ -d "$WS_DIR" ]]; then
  ws_count=$(ls -1 "$WS_DIR" 2>/dev/null | wc -l | tr -d ' ')
  emit_finding "$MODULE" "INFO" "J.3.cursor.ws" "Cursor has $ws_count workspace storage entries (per-project chat)" "" "" ""

  if [[ "$HAS_SQLITE" -eq 1 ]]; then
    leaky_ws=0
    while IFS= read -r dbf; do
      [[ -z "$dbf" ]] && continue
      if sqlite3 "$dbf" "SELECT value FROM ItemTable WHERE key IN ('aiService.prompts', 'workbench.panel.aichat.view.aichat.chatdata');" 2>/dev/null \
        | grep -qE "$GREP_PATTERN"; then
        leaky_ws=$((leaky_ws+1))
      fi
    done < <(find "$WS_DIR" -name 'state.vscdb' 2>/dev/null | head -50)

    if [[ "$leaky_ws" -gt 0 ]]; then
      emit_finding "$MODULE" "HIGH" "J.3.cursor.wsleak" \
        "$leaky_ws Cursor workspace state file(s) contain likely secrets in chat history" \
        "Per-project chat persists secrets even after you 'delete' chats in UI (Medium article — chats not truly deleted)." \
        "Wipe affected workspace storage entries. Future: never paste credentials into Cursor chat — use file references with env vars instead." \
        ""
    fi
  fi
fi

# ---------- J.4: Other AI tool session storage ----------
# Aider
[[ -f "$HOME/.aider.input.history" ]] && scan_file_for_secrets "$HOME/.aider.input.history" "Aider input history" "HIGH"
[[ -f "$HOME/.aider.chat.history.md" ]] && scan_file_for_secrets "$HOME/.aider.chat.history.md" "Aider chat history" "HIGH"

# Cline (VSCode extension)
CLINE_DIRS=("$HOME/.vscode/extensions" "$HOME/Library/Application Support/Code/User/globalStorage")
for d in "${CLINE_DIRS[@]}"; do
  [[ -d "$d" ]] || continue
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if grep -qE "$GREP_PATTERN" "$f" 2>/dev/null; then
      emit_finding "$MODULE" "MEDIUM" "J.4.cline" \
        "Possible secret in Cline state: $f" \
        "" "Inspect manually." ""
    fi
  done < <(find "$d" -path '*cline*' -type f -name '*.json' 2>/dev/null | head -20)
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
