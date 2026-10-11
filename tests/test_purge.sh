#!/usr/bin/env bash
# purge-secrets.sh: dry-run changes nothing; --purge redacts in place, keeps line counts
# and JSONL validity, leaves local DB URLs alone and stores backups privately;
# --delete-lines keeps the old behaviour.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home
export AUDIT_DIR="$OUT"

gh=$(fake_secret ghp_ 36 'A-Za-z0-9')
aws=$(fake_secret AKIA 16 'A-Z0-9')
ant=$(fake_secret sk-ant- 60 'A-Za-z0-9')
db_remote="postgres://admin:$(fake_secret '' 16 'A-Za-z0-9')@prod.example.com"
db_local="postgres://dev:dev@localhost"

SESSION="$HOME/.claude/projects/-home-me-app/1111-2222.jsonl"
ENVSNAP="$HOME/.claude/file-history/abc/.env"

make_fixtures() {
  rm -rf "$HOME/.claude" "$HOME/.bash_history"
  printf 'ls\nexport GH_TOKEN=%s\npsql %s:5432/app\n' "$gh" "$db_local" > "$HOME/.bash_history"
  mkdir -p "$(dirname "$SESSION")" "$(dirname "$ENVSNAP")"
  {
    printf '{"uuid":"a","parentUuid":null,"message":"hello"}\n'
    printf '{"uuid":"b","parentUuid":"a","message":"key %s and %s:5432/app"}\n' "$aws" "$db_remote"
    printf '{"uuid":"c","parentUuid":"b","message":"done"}\n'
  } > "$SESSION"
  printf 'ANTHROPIC_API_KEY=%s\n' "$ant" > "$ENVSNAP"
}

sums() { cat "$HOME/.bash_history" "$SESSION" "$ENVSNAP" | cksum; }

# --- dry-run ---
make_fixtures
before=$(sums)
bash "$SCRIPTS/purge-secrets.sh" > "$T/dry.log" 2>&1
assert_eq "$before" "$(sums)" "dry-run leaves files untouched"
assert_grep 'Lines containing secrets: 3' "$T/dry.log" "dry-run counts 3 lines (history, session, snapshot)"
assert_not_grep "$gh|$aws|$ant" "$T/dry.log" "dry-run output shows fingerprints only"

# --- purge (redact in place) ---
bash "$SCRIPTS/purge-secrets.sh" --purge --no-prompt > "$T/purge.log" 2>&1
assert_eq 3 "$(wc -l < "$HOME/.bash_history" | tr -d ' ')" "history keeps its line count"
assert_eq 3 "$(wc -l < "$SESSION" | tr -d ' ')" "session keeps its line count"
assert_true "every session line is still valid JSON" \
  python3 -c 'import json,sys; [json.loads(l) for l in open(sys.argv[1])]' "$SESSION"
assert_eq "" "$(grep -lF -e "$gh" -e "$aws" -e "$ant" -e "$db_remote" "$HOME/.bash_history" "$SESSION" "$ENVSNAP")" "no secret left in purged files"
assert_grep '\[REDACTED:ghp_' "$HOME/.bash_history"
assert_grep '\[REDACTED:AKIA' "$SESSION"
assert_grep '\[REDACTED:' "$ENVSNAP"
assert_grep "$db_local" "$HOME/.bash_history" "local DB URL is not purged"
assert_grep '"parentUuid":"b"' "$SESSION" "session chain intact"

backups="$OUT/purge-backups"
assert_eq 3 "$(find "$backups" -type f | wc -l | tr -d ' ')" "one backup per modified file"
assert_eq "" "$(find "$backups" -type f ! -perm 600)" "backups are mode 600"
assert_eq "" "$(find "$backups" -type d -perm -g+r)" "backup dirs are private"
assert_eq "" "$(find "$HOME" -name '*.bak.*')" "no backup next to the originals"
assert_grep 'Backups contain the original secrets' "$T/purge.log"

# --- purge --delete-lines (old behaviour) ---
make_fixtures
rm -rf "$backups"
bash "$SCRIPTS/purge-secrets.sh" --purge --delete-lines --no-backup --no-prompt > "$T/del.log" 2>&1
assert_eq 2 "$(wc -l < "$HOME/.bash_history" | tr -d ' ')" "delete-lines drops the secret line"
assert_eq 2 "$(wc -l < "$SESSION" | tr -d ' ')" "delete-lines drops the session line"
assert_file_absent "$backups"

report
