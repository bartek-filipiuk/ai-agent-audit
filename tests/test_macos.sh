#!/usr/bin/env bash
# macOS checks, exercised on any host: uname reports Darwin and the macOS tools are stubs
# with canned output. This verifies parsing logic, not real macOS behaviour (CI does that).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home
export AUDIT_DIR="$OUT"

real_uname=$(command -v uname)
stub_cmd uname "if [[ \"\${1:-}\" == -s ]]; then echo Darwin; else exec $real_uname \"\$@\"; fi"
for c in security spctl csrutil xattr; do stub_cmd "$c" 'exit 1'; done
stub_cmd brew 'exit 0'
stub_cmd mdutil 'echo "/:"; echo "	Indexing enabled."'

run_p() { mkdir -p "$OUT/findings"; : > "$OUT/findings/P.jsonl"; bash "$SCRIPTS/modules/P_macos.sh" > "$T/p.log" 2>&1; }
run_e() { bash "$SCRIPTS/modules/E_backup.sh" >/dev/null 2>&1; }

# The guard cannot be exercised here (BASH_VERSINFO is read-only); check it is in place.
assert_grep 'BASH_VERSINFO\[0\] < 4' "$SCRIPTS/lib/common.sh" "bash version guard in common.sh"
assert_grep 'BASH_VERSINFO\[0\] < 4' "$SCRIPTS/purge-secrets.sh" "bash version guard in purge-secrets.sh"

# --- TCC: modern schema (auth_value) is queried; an old-schema query would fail ---
TCC="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
mkdir -p "$(dirname "$TCC")"; : > "$TCC"
stub_cmd sqlite3 'q="${*: -1}"
case "$q" in
  *"SELECT 1"*) exit 0 ;;
  *auth_value*) echo "com.evil.helper|kTCCServiceSystemPolicyAllFiles|2" ;;
  *) exit 1 ;;
esac'
stub_cmd tmutil 'exit 1'
run_p
assert_finding P P.1.tcc
assert_grep 'com.evil.helper has Full Disk Access' "$OUT/findings/P.jsonl"

# TCC.db unreadable (no Full Disk Access) → explicit INFO instead of silence.
stub_cmd sqlite3 'exit 1'
run_p
assert_finding P P.1.tcc.unreadable

# --- LaunchAgents: com.apple.* in the user's dir is a masquerade; known vendors pass ---
LA="$HOME/Library/LaunchAgents"; mkdir -p "$LA"
: > "$LA/com.apple.softwareupdate.helper.plist"
: > "$LA/com.google.keystone.agent.plist"
: > "$LA/com.random.thing.plist"
run_p
assert_finding P P.2.masquerade
assert_grep 'Per-user launch agent claims to be Apple: [^"]*com.apple.softwareupdate.helper' "$OUT/findings/P.jsonl"
assert_not_grep 'com.google.keystone' "$OUT/findings/P.jsonl" "whitelisted vendor agent not reported"
assert_grep 'Unrecognized launch agent/daemon: [^"]*com.random.thing' "$OUT/findings/P.jsonl"

# --- Time Machine encryption comes from diskutil, per mounted destination ---
mkdir -p "$T/Volumes/TM"
stub_cmd tmutil "case \"\$1\" in
  destinationinfo) printf 'Name          : TM\nKind          : Local\nMount Point   : $T/Volumes/TM\nID            : X\n' ;;
  status) printf '{\n    Running = 0;\n}\n' ;;
  *) exit 0 ;;
esac"
stub_cmd diskutil 'printf "   Volume Name:   TM\n   Encrypted:     No\n"'
run_p
assert_finding P P.4.tm.unenc
stub_cmd diskutil 'printf "   Volume Name:   TM\n   FileVault:     Yes (Unlocked)\n"'
run_p
assert_no_finding P P.4.tm.unenc

# --- Spotlight + quarantine on .app bundles (directories) ---
mkdir -p "$HOME/Downloads/Tool.app/Contents"
run_p
assert_finding P P.6.spotlight
assert_finding P P.8.quarantine
assert_grep 'NO-QUARANTINE: \$1' "$OUT/findings/P.jsonl" "P.8 remediation keeps a literal dollar-one"

# --- E: idle Time Machine ("Running = 0;") must not count as an active backup ---
run_e
assert_no_finding E E.timemachine

report
