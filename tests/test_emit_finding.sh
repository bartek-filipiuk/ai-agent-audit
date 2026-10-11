#!/usr/bin/env bash
# emit_finding must always produce a valid JSON line, whatever bytes the evidence holds,
# on both escaping paths (jq, and the awk fallback used when jq is absent).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home

export AUDIT_DIR="$OUT"
source "$SCRIPTS/lib/common.sh"

# Original regression: CR and ESC used to produce a line jq rejects.
emit_finding T HIGH t.1 "title" $'carriage\rreturn and \x1b[0m escape' "fix"
assert_valid_json "$OUT/findings/T.jsonl"

decode_evidence() {  # last line of the file → .evidence, via python so it works without jq
  tail -n 1 "$1" | python3 -c 'import json,sys; sys.stdout.write(json.loads(sys.stdin.read())["evidence"])'
}

input=$'multi\nline\ttab "quote" back\\slash cr\r esc\x1b del\x7f zażółć €'
without_dropped=$'multi\nline\ttab "quote" back\\slash cr\r esc del zażółć €'

if [[ "$HAS_JQ" -eq 1 ]]; then
  emit_finding J HIGH j.1 "t" "$input" "r"
  assert_valid_json "$OUT/findings/J.jsonl"
  assert_eq "$input" "$(decode_evidence "$OUT/findings/J.jsonl")" "jq path round-trips every byte"
fi

# awk fallback, with each awk implementation available on this machine.
HAS_JQ=0
# Resolve real binaries first: once the awk stub exists, `awk` would resolve to the stub.
impls=()
for bin in awk mawk gawk busybox; do
  p=$(command -v "$bin" 2>/dev/null) || continue
  if [[ "$bin" == busybox ]]; then impls+=("$p awk"); else impls+=("$p"); fi
done
for impl in "${impls[@]}"; do
  bin=$(basename "${impl%% *}")
  stub_cmd awk "exec $impl \"\$@\""
  f="$OUT/findings/AWK_${bin}.jsonl"
  emit_finding "AWK_${bin}" HIGH a.1 "t" "$input" "r"
  assert_true "awk fallback ($impl) emits parseable JSON" \
    python3 -c 'import json,sys; [json.loads(l) for l in open(sys.argv[1])]' "$f"
  assert_eq "$without_dropped" "$(decode_evidence "$f")" "awk fallback ($impl) round-trip minus ESC/DEL"
done
rm -f "$T/stubs/awk"

report
