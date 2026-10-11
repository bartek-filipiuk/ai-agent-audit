#!/usr/bin/env bash
# Docs and reports state the score formula the code implements, grade colours follow the
# grade letters, and --skip-sessions really leaves module J out.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home
export AUDIT_DIR="$OUT"
source "$SCRIPTS/lib/common.sh"
source "$SCRIPTS/lib/html_report.sh"

for doc in README.md SKILL.md docs/usage-guide.md; do
  assert_true "$doc states the implemented score formula" grep -qF "${SCORE_FORMULA_TEXT#Score = }" "$REPO_ROOT/$doc"
  assert_not_grep '1\.7×HIGH|÷ 20|projects/\*/sessions/|10 modules|two outputs|Credentiale|skull on sub-50' \
    "$REPO_ROOT/$doc" "$doc has no stale claims"
done

# Formula numbers match the implementation: 1 CRIT, 2 HIGH, 10 MED, 20 LOW, 30 secrets,
# compound → 100 - 5 - 5 - 3 - 1 - 2 - 10 = 74
assert_eq 74 "$(compute_security_score 1 2 10 20 30 1)" "compute_security_score"

for pair in 95:S:grade-a 85:A:grade-a 75:B:grade-b 65:C:grade-c 55:D:grade-c 35:E:grade-d 25:F:grade-f; do
  IFS=: read -r score letter class <<<"$pair"
  g=$(compute_grade "$score")
  assert_eq "$letter" "${g%%$'\t'*}" "grade letter for $score"
  assert_eq "$class" "$(compute_grade_class "$score")" "colour class for $score"
done

unset AUDIT_DIR
bash "$SCRIPTS/run-audit.sh" --help > "$T/help.txt"
assert_grep 'skip-sessions' "$T/help.txt" "--help lists --skip-sessions"
printf 'export T=%s\n' "$(fake_secret ghp_ 36 'A-Za-z0-9')" > "$HOME/.bash_history"
run_audit --modules I,J --skip-sessions
assert_eq "I.jsonl X.jsonl " "$(cd "$OUT/findings" && ls | tr '\n' ' ')" "--skip-sessions drops J"
assert_file_absent "$OUT/secrets-inventory.md"

run_audit --modules I
assert_grep "$(printf '%s' "${SCORE_FORMULA_TEXT:0:40}" | sed 's/[]\.*^$()+?{}|[]/\\&/g')" "$OUT/audit-report.md" "Markdown report uses the shared formula text"
assert_grep 'distinct secrets ÷ 15' "$OUT/audit-report.html" "HTML report uses the shared formula text"

report
