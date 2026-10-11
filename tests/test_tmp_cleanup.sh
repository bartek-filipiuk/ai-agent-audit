#!/usr/bin/env bash
# Raw secret matches are written only to a private temp dir under the output directory,
# which is gone after the run — also after an interrupt — and the output dir is 700.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home

token=$(fake_secret ghp_ 36 'A-Za-z0-9')
printf 'ls\nexport GITHUB_TOKEN=%s\n' "$token" > "$HOME/.bash_history"
# Many session files so module J runs long enough to be interrupted mid-scan.
for i in $(seq 1 400); do
  d="$HOME/.claude/projects/-home-p$((i % 20))"
  mkdir -p "$d"
  printf '{"type":"user","message":"use %s please","n":%d}\n' "$token" "$i" > "$d/s$i.jsonl"
done

marker="$T/marker"; : > "$marker"
leaked_in_tmp() {  # top-level files in the system temp dir created during the test that hold the token
  local d="${TMPDIR:-/tmp}"
  find "$d" -maxdepth 1 -type f -newer "$marker" -user "$(id -u)" -print0 2>/dev/null \
    | xargs -0 grep -lF "$token" 2>/dev/null
}

run_audit --modules J
assert_finding J J.leak
assert_file_absent "$OUT/tmp"
assert_eq "" "$(leaked_in_tmp)" "no raw secret in the system temp dir after a normal run"
assert_eq "drwx------" "$(ls -ld "$OUT" | cut -c1-10)" "output dir is private"
assert_eq "" "$(find "$OUT" -type f -perm -g+r 2>/dev/null)" "no report file is group-readable"

# Interrupted standalone module run.
rm -rf "$OUT"
export AUDIT_DIR="$OUT"
timeout -s INT 0.5 bash "$SCRIPTS/modules/J_history_sessions.sh" >/dev/null 2>&1
unset AUDIT_DIR
left=$(find "$OUT/tmp" -type f 2>/dev/null)
assert_eq "" "$left" "no temp file left under the output dir after SIGINT"
assert_eq "" "$(leaked_in_tmp)" "no raw secret in the system temp dir after SIGINT"

report
