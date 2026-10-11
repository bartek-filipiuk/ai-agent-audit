#!/usr/bin/env bash
# Project roots come from the agents' own project lists, collapse crowded parents, never
# include $HOME itself, honour AUDIT_DEV_PATHS, and are reported in an X.roots finding.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home

mkdir -p "$HOME/work-a/p1" "$HOME/work-a/p2" "$HOME/work-a/p3" "$HOME/work-a/p4" "$HOME/solo" \
         "$HOME/codex-only" "$HOME/work-a/p3/.claude" "$T/outside/proj"
cat > "$HOME/.claude.json" <<JSON
{"projects": {"$HOME": {}, "$HOME/work-a/p1": {}, "$HOME/work-a/p2": {}, "$HOME/work-a/p3": {},
              "$HOME/work-a/p4": {}, "$HOME/solo": {}, "$HOME/gone": {}, "$T/outside/proj": {}}}
JSON
mkdir -p "$HOME/.codex"
printf '[projects."%s"]\ntrust_level = "trusted"\n' "$HOME/codex-only" > "$HOME/.codex/config.toml"
printf '{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}\n' \
  > "$HOME/work-a/p3/.claude/settings.json"

roots() { bash -c 'source "$SCRIPTS/lib/common.sh" >/dev/null 2>&1; printf "%s\n" "${DEV_SEARCH_PATHS[@]}"' ; }
export AUDIT_DIR="$OUT"
got=$(roots)
expected=$(printf '%s\n' "$T/outside/proj" "$HOME/codex-only" "$HOME/solo" "$HOME/work-a" | sort)
assert_eq "$expected" "$got" "roots: crowded parent collapsed, \$HOME and missing dirs dropped, Codex added"

got=$(AUDIT_DEV_PATHS="$HOME/solo" roots)
assert_eq "$HOME/solo" "$got" "AUDIT_DEV_PATHS overrides everything"
unset AUDIT_DIR

run_audit --modules K
assert_finding X X.roots
assert_grep "$HOME/work-a" "$OUT/findings/X.jsonl"
assert_grep '"id":"K.2.risky","title":"[^"]*work-a/p3' "$OUT/findings/K.jsonl" "repo under a derived root is scanned"

report
