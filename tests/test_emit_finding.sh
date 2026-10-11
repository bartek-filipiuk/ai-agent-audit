#!/usr/bin/env bash
# emit_finding must always produce a valid JSON line, whatever bytes the evidence holds.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home

export AUDIT_DIR="$OUT"
source "$SCRIPTS/lib/common.sh"
emit_finding T HIGH t.1 "title" $'carriage\rreturn and \x1b[0m escape' "fix"
assert_valid_json "$OUT/findings/T.jsonl"

report
