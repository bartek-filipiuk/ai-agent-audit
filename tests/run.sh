#!/usr/bin/env bash
# Runs every tests/test_*.sh in its own process. Exit 1 if any test file fails.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

# Per-file limit, when a timeout binary exists, so one hung test cannot stall CI.
to=$(command -v timeout || command -v gtimeout || true)
failed=()
for t in test_*.sh; do
  printf '%s\n' "$t"
  if ${to:+"$to" 900} bash "$t"; then
    printf '  PASS\n'
  else
    printf '  FAIL\n'
    failed+=("$t")
  fi
done

echo
if [[ ${#failed[@]} -gt 0 ]]; then
  printf 'FAILED: %s\n' "${failed[*]}"
  exit 1
fi
echo "All tests passed."
