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

report
