#!/usr/bin/env bash
# Shared helpers for the test suite. Source this from a tests/test_*.sh file.
#
# Every test runs against a throwaway HOME so the audit never touches the real
# machine. Commands that read real account state or hit the network (gh, npm, pip,
# sudo, ssh-add, op, bw) are replaced by failing stubs; a test that needs one of
# them overrides the stub with stub_cmd.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$REPO_ROOT/scripts"
export REPO_ROOT SCRIPTS

_PASS=0
_FAIL=0

# Creates $T (scratch root), $HOME=$T/home, $OUT=$T/out and a stub dir on PATH.
# AUDIT_DIR is deliberately NOT exported: tests that exercise --output must prove
# that the flag alone routes every artefact.
make_fake_home() {
  T=$(mktemp -d)
  export T
  export HOME="$T/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  OUT="$T/out"
  export OUT
  mkdir -p "$HOME" "$T/stubs"
  unset AUDIT_DIR FINDINGS_DIR SECRETS_INVENTORY SSH_AUTH_SOCK GH_TOKEN GITHUB_TOKEN \
        HTTP_PROXY HTTPS_PROXY http_proxy https_proxy CODESPACES REMOTE_CONTAINERS_IPC \
        WSL_DISTRO_NAME AUDIT_DEV_PATHS
  export PATH="$T/stubs:$PATH"
  local c
  for c in gh npm pip pip3 sudo ssh-add op bw kubectl; do
    stub_cmd "$c" 'exit 1'
  done
  trap 'rm -rf "$T"' EXIT
}

# stub_cmd <name> <bash body>
stub_cmd() {
  printf '#!/usr/bin/env bash\n%s\n' "$2" > "$T/stubs/$1"
  chmod +x "$T/stubs/$1"
}

# fake_secret <prefix> <length> <tr charset> — random token built at test time so no
# real-looking credential is ever committed to the repository.
fake_secret() {
  local rand
  rand=$(LC_ALL=C tr -dc "$3" < /dev/urandom | head -c "$2")
  printf '%s%s' "$1" "$rand"
}

# run_audit [args...] — runs the orchestrator quietly, output under $OUT.
# Modules get a time limit so a hang shows up as a named failure instead of a stuck run.
run_audit() {
  AUDIT_MODULE_TIMEOUT="${AUDIT_MODULE_TIMEOUT:-120}" \
    bash "$SCRIPTS/run-audit.sh" --no-open --output "$OUT" "$@" >"$T/run.log" 2>&1
  grep -E 'timed out|exited with non-zero' "$T/run.log" | sed 's/^/    run-audit: /' || true
}

_ok()   { _PASS=$((_PASS+1)); }
_fail() { _FAIL=$((_FAIL+1)); printf '    FAIL: %s\n' "$1"; }

assert_true() {  # assert_true <description> <command...>
  local desc="$1"; shift
  if "$@"; then _ok; else _fail "$desc"; fi
}

assert_file()        { if [[ -f "$1" ]]; then _ok; else _fail "expected file: $1"; fi; }
assert_file_absent() { if [[ ! -e "$1" ]]; then _ok; else _fail "expected absent: $1"; fi; }

assert_grep() {      # assert_grep <ERE> <file> [description]
  if grep -qE -- "$1" "$2" 2>/dev/null; then _ok; else _fail "${3:-expected /$1/ in $2}"; fi
}
assert_not_grep() {
  if ! grep -qE -- "$1" "$2" 2>/dev/null; then _ok; else _fail "${3:-unexpected /$1/ in $2}"; fi
}

assert_eq() {        # assert_eq <expected> <actual> <description>
  if [[ "$1" == "$2" ]]; then _ok; else _fail "$3 (expected '$1', got '$2')"; fi
}

# Every line of a JSONL file and every JSON file must parse.
assert_valid_json() {
  local f="$1"
  if [[ ! -f "$f" ]]; then _fail "missing JSON file: $f"; return; fi
  if command -v jq >/dev/null 2>&1; then
    if jq empty "$f" >/dev/null 2>&1; then _ok; else _fail "invalid JSON: $f"; fi
  else
    if python3 -c 'import json,sys
for l in open(sys.argv[1]):
    l=l.strip()
    l and json.loads(l)' "$f" 2>/dev/null; then _ok; else _fail "invalid JSON: $f"; fi
  fi
}

assert_finding() {      # assert_finding <module> <id>
  assert_grep "\"id\":\"$2\"" "$OUT/findings/$1.jsonl" "expected finding $1/$2"
}
assert_no_finding() {
  assert_not_grep "\"id\":\"$2\"" "$OUT/findings/$1.jsonl" "unexpected finding $1/$2"
}

# Call at the end of every test file.
report() {
  printf '    %d passed, %d failed\n' "$_PASS" "$_FAIL"
  [[ "$_FAIL" -eq 0 ]]
}
