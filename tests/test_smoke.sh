#!/usr/bin/env bash
# Full run against an empty fake HOME: every artefact lands in --output, nothing in
# the default ~/.ai-agent-audit, and the JSON report parses.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home

run_audit
assert_file "$OUT/audit-report.json"
assert_file "$OUT/audit-report.md"
assert_file "$OUT/audit-report.html"
assert_file "$OUT/action-plan.md"
assert_valid_json "$OUT/audit-report.json"
assert_file_absent "$HOME/.ai-agent-audit"

# A second, partial run must not aggregate stale findings from the first one.
run_audit --modules I
findings_files=$(cd "$OUT/findings" && ls)
assert_eq "I.jsonl" "$findings_files" "partial run leaves only its own findings file"
if command -v jq >/dev/null 2>&1; then
  assert_eq "I" "$(jq -r .modules_run "$OUT/audit-report.json")" "modules_run lists the partial run"
  total=$(jq '[.summary.critical,.summary.high,.summary.medium,.summary.low,.summary.info]|add' "$OUT/audit-report.json")
  assert_eq "$(wc -l < "$OUT/findings/I.jsonl" | tr -d ' ')" "$total" "summary counts only module I findings"
fi
assert_grep 'Partial run' "$T/run.log"

report
