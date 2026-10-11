#!/usr/bin/env bash
# One key found in two places is one secret; MCP configs are checked by value and by shape.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
make_fake_home
command -v jq >/dev/null 2>&1 || { echo "    (skipped: needs jq)"; report; exit; }

tok=$(fake_secret ghp_ 36 'A-Za-z0-9')
printf 'export GH=%s\n' "$tok" > "$HOME/.bash_history"
mkdir -p "$HOME/.claude/projects/-p"
printf '{"m":"%s"}\n' "$tok" > "$HOME/.claude/projects/-p/s.jsonl"
# A base64url blob that happens to contain "hf_" + 30 chars is not a token.
blob="gAAAAAB$(fake_secret '' 20 'A-Za-z0-9')hf_$(fake_secret '' 34 'A-Za-z0-9')"
printf '{"encrypted_content":"%s"}\n' "$blob" >> "$HOME/.claude/projects/-p/s.jsonl"

run_audit --modules J
assert_eq 1 "$(jq .summary.secrets_distinct "$OUT/audit-report.json")" "same key in two sources counts once, blob fragment not counted"
assert_eq 2 "$(jq .summary.secrets_occurrences "$OUT/audit-report.json")" "occurrences are still reported"
assert_eq 1 "$(jq '.secrets_inventory_summary[0].count' "$OUT/audit-report.json")" "per-type summary dedupes too"

# MCP configs: a known token format under an env key, an unknown format passed as a flag,
# and an env reference that must not count.
pat=$(fake_secret ghp_ 36 'A-Za-z0-9')
cat > "$HOME/.claude.json" <<EOF
{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-mcp@1.0.0"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "$pat"}}}}
EOF
mkdir -p "$HOME/projects/a" "$HOME/projects/b"
printf '{"mcpServers": {"x": {"command": "npx", "args": ["-y", "x-mcp@1.0.0", "--api-key", "zz9Qm4Lr8Tp2Wn7K"]}}}\n' > "$HOME/projects/a/.mcp.json"
printf '{"mcpServers": {"y": {"command": "npx", "args": ["-y", "y-mcp@1.0.0"], "env": {"API_KEY": "${MY_KEY}"}}}}\n' > "$HOME/projects/b/.mcp.json"

run_audit --modules M
assert_grep '"id":"M.3.plaintext_secrets","title":"[^"]*\.claude\.json' "$OUT/findings/M.jsonl" "known token under an env key"
assert_grep 'GitHub Classic PAT' "$OUT/secrets-inventory.md"
assert_grep '"id":"M.3.plaintext_secrets","title":"[^"]*projects/a/' "$OUT/findings/M.jsonl" "--api-key literal in args"
assert_grep 'command-line flag' "$OUT/findings/M.jsonl"
assert_not_grep '"id":"M.3.plaintext_secrets","title":"[^"]*projects/b/' "$OUT/findings/M.jsonl" "\${VAR} reference is not a secret"
assert_eq "" "$(grep -rlF -e "$pat" -e zz9Qm4Lr8Tp2Wn7K "$OUT")" "no raw value in any artefact"

report
