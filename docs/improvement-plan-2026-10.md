# Improvement plan — October 2026

Execution plan for an autonomous agent (Opus 5.5). Work top to bottom, one task per
commit, run the verification block of every task before committing, push to
`origin main` only in the final task after everything passes. Written from a review
done on 2026-10-11; every defect below was traced in code and the top items were
reproduced by running the scripts.

## Ground rules

- **Branch:** work directly on `main` locally. Push once, at the end (T13). If the push
  is rejected (auth, protection, non-fast-forward), stop and report; do not force.
- **Commits:** one per task, message = the `Commit:` line of the task. English,
  imperative, no AI footer of any kind (no `Co-Authored-By`, no "Generated with").
- **Never run the audit against the real `$HOME` during development.** Use the test
  harness from T1 (fake `HOME`) and `--output` into a scratch directory. The only run
  against the real home is the final smoke test in T13, with `--no-open`.
- **Line numbers in this plan are from 2026-10-11.** They drift as you edit. Locate each
  site by the quoted code, not by the number.
- **Bash stays bash.** No rewrite to Python, no plugin framework, no new dependencies.
  `jq`, `python3`, `perl` remain optional with the existing fallback chain.
- **Every behaviour change gets a test** in `tests/` (T1 harness). A task is done when
  its test fails on the old code and passes on the new code. Mention that in the commit
  body when relevant.
- **Fixture secrets are generated at test time, never committed.** GitHub push
  protection blocks commits that contain real-looking `AKIA…`, `ghp_…`, `sk_live_…`
  tokens. Fixtures build them with `printf` + `/dev/urandom` (see T1).
- **Docs follow code in the same commit** (README.md, SKILL.md, docs/usage-guide.md).
  A doc that lies is a defect.
- Run `shellcheck -S warning` on every file you touch; fix or `# shellcheck disable=`
  with a one-line reason.

## Task list

| # | Task | Area |
|---|------|------|
| T1 | Test harness + shellcheck CI | infra |
| T2 | `--output` routing and per-run findings reset | core bug |
| T3 | JSON escaping in `emit_finding` (control chars, BSD sed) | core bug |
| T4 | Redact secret values in all evidence; stop echoing untrusted text | tool security |
| T5 | Temp files with raw matches: `trap` + private `TMPDIR` | tool security |
| T6 | `purge-secrets.sh`: redact in place, private backups, correct paths | tool security |
| T7 | bash ≥ 4 guard + macOS fixes (BSD sed, TCC schema, LaunchAgents, tmutil) | portability |
| T8 | Dead checks: N anchors, M project-scope + remote servers, permissions schema, ufw, npm token, gh limit, `halt` | detection |
| T9 | Dev roots from `~/.claude.json`; scanned-roots INFO finding | detection |
| T10 | False positives and coverage gaps (regexes, skills enumeration, new paths) | detection |
| T11 | Secrets counting: dedupe by fingerprint; B/M use `secrets.sh` | detection |
| T12 | Score/grade consistency and docs sync (SKILL.md, README, usage-guide) | docs |
| T13 | Final full run, CHANGELOG, push | release |

---

## T1 — Test harness + shellcheck CI

**Why.** There are zero tests, which is why a dozen checks died silently. Everything
after this task adds a test here.

**Changes.**

1. `tests/lib.sh` — helpers:
   - `make_fake_home` creates `$T/home` under a `mktemp -d` and exports `HOME="$T/home"`
     and `AUDIT_DIR="$T/out"`. It must also set `XDG_CONFIG_HOME="$HOME/.config"`.
   - `fake_secret <prefix> <len> <charset>` — e.g.
     `fake_secret AKIA 16 'A-Z0-9'` → `printf '%s%s' "$prefix" "$(LC_ALL=C tr -dc "$charset" < /dev/urandom | head -c "$len")"`.
   - `assert_finding <module> <id>` / `assert_no_finding <module> <id>` — grep
     `"id":"<id>"` in `$AUDIT_DIR/findings/<module>.jsonl`.
   - `assert_valid_json <file>` — `jq empty` (skip with a notice if `jq` missing).
   - `assert_file_absent`, `assert_grep`, `assert_not_grep`.
   - Counter + `report` that exits non-zero on any failure.
2. `tests/run.sh` — runs every `tests/test_*.sh` in a subshell, prints PASS/FAIL per
   file, exits 1 on any failure. Must work with `bash tests/run.sh` from the repo root.
3. First tests (they document current behaviour and will be extended by later tasks):
   - `tests/test_smoke.sh` — fake home with nothing in it; run
     `bash scripts/run-audit.sh --no-open --output "$AUDIT_DIR"`; assert
     `audit-report.json` exists in `$AUDIT_DIR` and is valid JSON; assert nothing was
     created under the real `~/.ai-agent-audit` (compare mtime before/after, or run with
     `HOME` pointing at the fake home so the default would also land in the fake home).
     This test FAILS today (T2 fixes it) — mark it `# expected to fail until T2` and make
     `run.sh` still exit non-zero; do not skip it.
   - `tests/test_emit_finding.sh` — source `scripts/lib/common.sh` with
     `AUDIT_DIR=$T/out`; `emit_finding T HIGH t.1 title $'a\rb\x1bc' fix`; assert the
     jsonl is valid JSON. FAILS today (T3 fixes it).
4. `.github/workflows/ci.yml` — on push and PR: `ubuntu-latest` and `macos-latest`
   matrix; steps: checkout, install shellcheck (apt / brew), install `jq` on macOS
   (`brew install jq bash`), `shellcheck -S warning scripts/*.sh scripts/lib/*.sh scripts/modules/*.sh tests/*.sh`,
   `bash tests/run.sh`. On macOS run tests with Homebrew bash explicitly:
   `/opt/homebrew/bin/bash tests/run.sh || /usr/local/bin/bash tests/run.sh`.
5. README: add a "Development" section with `bash tests/run.sh` and `shellcheck` commands.

**Verification.**
```bash
bash tests/run.sh            # 2 tests fail (smoke, emit_finding) with clear messages, exit 1
shellcheck -S warning tests/*.sh
```
If `shellcheck` is not installed locally: `sudo apt-get install -y shellcheck` or use
`npx --yes shellcheck` is NOT acceptable (it's a different tool); install the real one or
let CI run it and note that in the commit body.

**Commit:** `Add test harness, first regression tests and shellcheck CI`

---

## T2 — `--output` routing and per-run findings reset

**Why.** Reproduced: `run-audit.sh --modules I --output /x --no-open` left `/x`
empty and wrote `I.jsonl` and all reports into `~/.ai-agent-audit`, and the aggregate
included stale findings from a previous full run (HIGH=6, 62 secrets for a one-module
run). Cause: `AUDIT_DIR` is never exported (`run-audit.sh:16`, `common.sh:6`) while
modules and `aggregate.sh` are separate `bash` processes. Violates the README "Hard
guarantees" (read-only outside the output directory).

**Changes.**

1. `scripts/run-audit.sh`: after argument parsing, `export AUDIT_DIR FINDINGS_DIR`.
   Also move `mkdir -p "$FINDINGS_DIR"` out of the `--output` branch to right after
   parsing (common.sh already created the default dir before parsing; that is fine, but
   delete the empty default dir again if `--output` was given and the default dir was
   created by this run and is empty — simplest: in `common.sh` do not `mkdir` at source
   time; create directories in `run-audit.sh` and in `emit_finding` lazily with
   `mkdir -p "$(dirname "$out")"`).
2. Reset findings per run: in `run-audit.sh` before the module loop,
   `rm -f "$FINDINGS_DIR"/*.jsonl`. Print one line when `MODULES_TO_RUN` is not the full
   list: `Partial run: score and reports reflect only modules <list>.` Also write
   `"modules_run": "<list>"` into `audit-report.json` (aggregate.sh gets it via an exported
   `MODULES_RUN` variable; default to `ALL_MODULES` when unset).
3. `scripts/aggregate.sh`: it is invoked as a subprocess; it now inherits `AUDIT_DIR`.
   Add a guard at the top: if `AUDIT_DIR` is unset, fall back as today but `warn` once.

**Verification.**
```bash
bash tests/run.sh                                   # test_smoke now passes
# manual: fake home + custom output, prove the default dir is untouched
T=$(mktemp -d); HOME=$T/home bash scripts/run-audit.sh --modules I --output $T/out --no-open
ls $T/out/findings/I.jsonl $T/out/audit-report.json   # exist
ls $T/home/.ai-agent-audit 2>&1                       # No such file
```
Extend `tests/test_smoke.sh`: run twice, second time with `--modules I`, assert that
`findings/` contains only `I.jsonl` and `summary.*` counts match that single module.

**Commit:** `Fix --output routing and reset findings at the start of every run`

---

## T3 — JSON escaping in `emit_finding`

**Why.** Reproduced: evidence containing `\r` or `\x1b` makes `jq` reject the line
("control characters … must be escaped"), which breaks `audit-report.json` entirely
(aggregate embeds raw lines) and blanks the finding in MD/HTML because
`json_decode_field` returns "". The `sed ':a;N;$!ba;…'` idiom in `common.sh:42` is
also GNU-only; BSD sed errors on it, so on macOS every field would be empty and the
host would score 100/S.

**Changes.**

1. Replace `esc()` in `scripts/lib/common.sh` with:
   - if `HAS_JQ`: `printf '%s' "$1" | jq -Rs . | sed -e 's/^"//' -e 's/"$//'`
     (`-R -s` reads the whole input as one string and emits a correctly escaped JSON
     string literal).
   - else: single `awk` pass that escapes `\`, `"`, `\t`, `\r`, `\n` and drops every
     other byte in `0x00–0x1F` and `0x7F`. One awk program, portable (no GNU
     extensions), e.g. build the output with `gsub` on `\\`, `"`, `\t`, `\r`, then join
     lines with `\\n`, then `gsub(/[\001-\010\013\014\016-\037\177]/, "")`.
2. Grep all modules for literal `\n` inside double-quoted evidence strings
   (`K_hooks.sh:32`, `:102`, `:109` and any other hit of `grep -n '\\n' scripts/modules`)
   and replace with `$'\n'` concatenation or `printf -v`.
3. `scripts/aggregate.sh`: when `HAS_JQ`, validate the final `audit-report.json` with
   `jq empty` and `err` loudly if it fails (do not exit non-zero; the MD/HTML are still
   useful).

**Verification.**
```bash
bash tests/run.sh                 # test_emit_finding passes
# extend test_emit_finding: a multi-line evidence, a tab, a quote, a backslash, a \x7f, non-ASCII
# → jq -r .evidence must round-trip to the original minus the dropped control bytes
```
Add a second case that runs with `PATH` stripped of `jq` (`PATH=/usr/bin:/bin` with a
temp dir shadowing `jq` by a failing stub) to exercise the awk fallback, same assertions
via `python3 -c 'import json,sys; json.loads(sys.stdin.read())'`.

**Commit:** `Make emit_finding JSON-safe for control characters and BSD sed`

---

## T4 — Redact secret values in evidence; stop echoing untrusted text

**Why.** `M_mcp.sh` writes `"Command: $cmd $args"` into evidence (lines 92, 98, 107,
114, 119, 124); MCP args routinely carry `--api-key sk-…` or
`--header "Authorization: Bearer …"`. `K_hooks.sh:29-32,155,158,165,168`,
`L_skills.sh:84,87`, `P_macos.sh:82-87` copy raw hook commands / matched
prompt-injection lines / plist ProgramArguments into evidence. That (a) writes secret
values to disk, contradicting the README guarantee, and (b) hands text written by an
attacker in a cloned repo straight into the report an AI agent will read.

**Changes.**

1. `scripts/lib/common.sh`: source `lib/secrets.sh` at the end of common.sh (it only
   depends on `AUDIT_DIR`; check there is no circular source — `secrets.sh` must not
   source `common.sh`). Then in `emit_finding`, before escaping, run `title`,
   `evidence` and `remediation` through
   `redact_secrets_in_text()` = `sed -E "s#($SECRETS_GREP_PATTERN)#[REDACTED]#g"`.
   Use a delimiter that does not appear in the pattern (`#` appears nowhere in
   `SECRET_PATTERNS`; verify with grep before relying on it). Keep the original
   modules' intent; this is a safety net at the single choke point.
2. `M_mcp.sh`: evidence becomes `Launcher: <cmd>  Package: <first non-flag arg>` and
   never the full args. Keep the full args only for the `npx` version-pinning test
   (already in memory, not persisted).
3. `K_hooks.sh`, `L_skills.sh`, `P_macos.sh`: wherever a matched line from an untrusted
   file is emitted, replace with `<file>:<line-number>` plus a snippet of at most 80
   characters, prefixed with `[untrusted content] `. Implement a shared helper in
   `common.sh`: `untrusted_snippet <file> <lineno> [max=80]` that reads the line, strips
   control characters, truncates, prefixes.
4. README "Hard guarantees": add one sentence — evidence strings are passed through the
   secret-pattern redactor and untrusted file content is truncated and labelled.

**Verification.** New `tests/test_redaction.sh`:
- fake home with `~/.claude.json` containing an MCP server
  `{"command":"npx","args":["-y","mcp-remote","https://x","--header","Authorization: Bearer <fake ghp_>"]}`
  → run `--modules M`; assert the fake token string is absent from every file under
  `$AUDIT_DIR` (`grep -r "$TOKEN" "$AUDIT_DIR"` returns nothing) and `M.2.*` finding exists.
- fake repo under a scanned root (see T9; until then put it in `$HOME/projects/x`) with
  `.claude/settings.json` hook command containing a fake `AKIA…` and a 500-char line →
  run `--modules K`; assert `[REDACTED]`, `[untrusted content]`, and no evidence field
  longer than ~200 chars.

**Commit:** `Redact secret values in all findings and label untrusted snippets`

---

## T5 — Temp files with raw matches

**Why.** `secrets.sh:238` appends raw secret matches to a `mktemp` file in `/tmp`;
`:221-222` copies the whole Cursor DB / Atuin stdin to `/tmp`. No `trap`, so Ctrl-C or
an error leaves plaintext secrets on disk, contradicting the header comment "raw values
live only in memory".

**Changes.**

1. `scripts/lib/secrets.sh`: at source time set
   `export TMPDIR="${AUDIT_DIR}/tmp"`, `mkdir -p "$TMPDIR" && chmod 700 "$TMPDIR"`.
   In every function that calls `mktemp`, register cleanup:
   `trap 'rm -f "$merged" "$tmp_table"' RETURN` is bash ≥ 4.4 only for functions with
   `RETURN`; simpler and portable: keep a global array `_SECRETS_TMPFILES+=("$f")` and
   a single `trap '_secrets_cleanup' EXIT INT TERM` installed once at source time that
   `rm -f`s all of them and the `TMPDIR` if empty.
2. `scripts/run-audit.sh`: at the very end (and in a `trap … EXIT`) `rm -rf "$AUDIT_DIR/tmp"`.
3. `chmod 700 "$AUDIT_DIR"` and `chmod 600` on every report file when created
   (`aggregate.sh`, `html_report.sh`, `action_plan.sh`, `secrets.sh` inventory). The
   reports contain paths and fingerprints; other local users should not read them.

**Verification.** `tests/test_tmp_cleanup.sh`: run module J against a fake home with a
`.bash_history` containing a fake token; after the run assert `$AUDIT_DIR/tmp` does not
exist and `find /tmp -maxdepth 1 -newer <marker> -user $USER` (where `<marker>` is a file
created before the run) lists nothing from the audit. Also simulate an interrupt:
`timeout -s INT 0.3 bash scripts/modules/J_history_sessions.sh` in a fake home with a
big history; assert no leftover under `$AUDIT_DIR/tmp` and nothing new in `/tmp`.
Assert `stat -c %a "$AUDIT_DIR"` = `700`.

**Commit:** `Keep raw secret matches in a private tmp dir and clean up on exit`

---

## T6 — `purge-secrets.sh`: redact in place, private backups, correct paths

**Why.** (a) `purge_file` copies the file to `<file>.bak.<TS>` next to the original
and never removes it; the leaked secret stays on disk with the same reachability.
(b) Deleting whole lines from Claude Code session JSONL removes messages and can break
the `parentUuid` chain used by `--resume`. (c) Comments and README cite
`~/.claude/projects/*/sessions/*.jsonl`; the real layout is
`~/.claude/projects/<encoded-cwd>/<uuid>.jsonl` (verified: zero `sessions/` dirs).
(d) `purge-secrets.sh` duplicates the pattern list instead of using `lib/secrets.sh`.

**Changes.**

1. Source `scripts/lib/secrets.sh` and build `HIGH_CONFIDENCE` from `SECRET_PATTERNS`
   by severity hint (`HIGH`/`CRITICAL` types only; keep the DB-URL local-host exclusion
   and the JWT opt-in as today). Delete the duplicated regex literals.
2. Default behaviour becomes **redact in place**: replace each match with
   `[REDACTED:<fingerprint>]` using `sed -E` on the match pattern (per-line, so JSONL
   structure and shell-history line count are preserved). Keep `--delete-lines` as an
   explicit opt-in for the old behaviour.
3. Backups go to `$AUDIT_DIR/purge-backups/<TS>/<path-with-slashes-as-__>` with
   `chmod 600`, directory `700`. Print at the end: `Backups contain the original secrets.
   After verifying, delete them: rm -rf <dir>`. Add `--no-backup`.
4. Fix all `sessions/` strings (purge header comment, README.md:63, README.md:165,
   SKILL.md:43, `J_history_sessions.sh:71` and `:89` remediation text) to
   `~/.claude/projects/*/*.jsonl`.
5. Also purge `~/.claude/file-history/**` (snapshots of edited files, where `.env`
   contents end up) and `~/.codex/history.jsonl`, `~/.codex/sessions/**/*.jsonl` when
   present — same redact-in-place path.

**Verification.** `tests/test_purge.sh`: fake home with `.bash_history` (3 lines, one
with a fake `ghp_`), a Claude session JSONL (3 JSON lines with `parentUuid` chain, one
containing a fake `AKIA`), `.claude/file-history/x/.env` with a fake `sk-ant-`.
- dry-run: files unchanged (checksums equal), output lists 3 matches.
- `--purge --no-prompt`: line counts unchanged; each JSONL line still valid JSON
  (`jq -c . file`); tokens absent; `[REDACTED:` present; backups under
  `$AUDIT_DIR/purge-backups` with mode 600; no `*.bak.*` next to originals.
- `--purge --delete-lines --no-prompt`: old behaviour, line count minus one.

**Commit:** `purge-secrets: redact in place, private backups, correct session paths`

---

## T7 — bash ≥ 4 guard and macOS fixes

**Why.** `declare -A` (`run-audit.sh:57`, `H_browser_session.sh:12,19`, `M_mcp.sh:54`)
and `mapfile` (`J_history_sessions.sh:74`) need bash 4; stock macOS `/bin/bash` is 3.2,
so the documented `bash scripts/run-audit.sh` dies on line 57 on a Mac without Homebrew
bash while README claims macOS support. Several macOS checks are dead:
`P_macos.sh:56-65` queries TCC.db with the pre-Big-Sur column `allowed` (now
`auth_value`); `:70,78,93` whitelists `com.apple.*` under `~/Library/LaunchAgents`, the
exact place malware masquerades; `:128-139` looks for an "Encrypted" field that
`tmutil destinationinfo` does not print; `E_backup.sh:22` `grep 'BackupPhase\|Running'`
always matches idle output `Running = 0;`.

**Changes.**

1. `scripts/lib/common.sh` top:
   `(( BASH_VERSINFO[0] >= 4 )) || { printf 'ai-agent-audit needs bash >= 4 (macOS: brew install bash, then run with /opt/homebrew/bin/bash)\n' >&2; exit 2; }`.
   README "Requirements": `bash >= 4` with the brew line. Quick start on macOS uses
   `$(brew --prefix)/bin/bash scripts/run-audit.sh`.
2. `P_macos.sh` TCC: `SELECT client, service, auth_value FROM access WHERE auth_value IN (2,3) AND service IN (...)`;
   when `sqlite3 "$USER_TCC" 'SELECT 1 FROM access LIMIT 1'` fails, emit INFO
   `P.1.tcc.unreadable` with "grant Terminal Full Disk Access and re-run".
3. `P_macos.sh` LaunchAgents: apply the vendor whitelist only to `/Library/LaunchAgents`
   and `/Library/LaunchDaemons`; under `$HOME/Library/LaunchAgents` any `com.apple.*`
   plist is HIGH `P.2.masquerade`.
4. `P_macos.sh` Time Machine encryption: for each destination mount point from
   `tmutil destinationinfo` (`Mount Point :` lines), `diskutil info "$mount" | grep -q 'Encrypted: *Yes'`;
   remove the unused `dest_name`.
5. `P_macos.sh` Spotlight: replace the `mdfind -onlyin dir '*'` check with
   `mdutil -s /` (indexing on/off) and drop `-type f` for `*.app` (bundles are dirs).
6. `E_backup.sh:22`: `grep -qE 'Running = 1;|BackupPhase'`.
7. Check every `stat`, `date`, `find -printf`, `sed -i`, `grep -P`, `readlink -f`
   usage added by later tasks against BSD; prefer the `$OS` branches already in
   `common.sh`.

**Verification.** `tests/test_bash_guard.sh`: run `common.sh` under a shim that sets
`BASH_VERSINFO`? Not possible (readonly). Instead: assert the guard line exists and
that `bash -n` passes; CI's macOS job with Homebrew bash is the real check. TCC/plist
logic: unit-test the parsing functions by feeding canned `tmutil`/`sqlite3` output
through a stub `PATH` (`tests/stubs/tmutil`, `tests/stubs/diskutil`) in a fake home;
assert `P.4.tm.unenc` fires for `Encrypted: No` and not for `Yes`; assert
`com.apple.foo.plist` under fake `~/Library/LaunchAgents` → `P.2.masquerade`.

**Commit:** `Require bash 4, fix dead macOS checks (TCC schema, LaunchAgents, Time Machine)`

---

## T8 — Dead or broken checks

Each item: fix + a test case in `tests/test_modules_<letter>.sh` (fixture that must
trigger, fixture that must not).

1. **`N_packages.sh:68`** — `ver_pat` values like `^1\.14\.1$` are embedded mid-regex
   (`"[~^=]?($ver_pat)"`), so anchors never match; `N.1.npm.workspace` can never fire.
   Store patterns without anchors in `NPM_COMPROMISED`/`PIP_COMPROMISED`; add `^…$` only
   where the whole token is compared (`:47`, `:90`). Also add a pass over
   `node_modules/<pkg>/package.json` `"version"` and over `package-lock.json`
   (`"node_modules/<pkg>": {"version": …}`) so resolved versions are checked, not just
   specs. Anchor `grep -E "${pkg}@"` at `:44` to `(^|[[:space:]─└├ ])${pkg_q}@`.
   Fix the extension glob to `*.prettier-vscode-plus-*` and drop the non-existent
   `~/.config/Code/User/extensions` path.
2. **Single IOC source.** Move the Nx version list out of `common.sh:157-166` into
   `N_packages.sh`'s table (or a new `scripts/data/ioc.tsv` read by both) so there is one
   list; delete `is_nx_compromised_version` duplication. Module G's Nx check calls the
   same function N uses.
3. **`M_mcp.sh:63-66`** — jq reads only top-level `.mcpServers`. Extend to project scope:
   iterate `.projects | to_entries[]` and emit findings labelled with the project path.
   Add `.value.type` and `.value.url` to the TSV; add an `http|sse)` case: INFO with the
   URL host, MEDIUM if scheme is not `https`. Remove the "unrecognized launcher: ?"
   false positive for remote servers.
4. **Permissions schema** (`B_ai_tools.sh:141-146`, `K_hooks.sh:65`): detect current
   Claude Code schema. With `jq`: `.permissions.defaultMode == "bypassPermissions"`,
   `.permissions.allow[]` matching `^Bash(\(\*?\))?$` or `Bash(*)`, `.env.ANTHROPIC_BASE_URL`
   (token exfil vector), `.skipDangerousPermissionCheck`. Without jq: grep the same keys.
   Files: `~/.claude/settings.json`, `~/.claude/settings.local.json`, repo
   `.claude/settings.json` and `.claude/settings.local.json`,
   `/etc/claude-code/managed-settings.json`. Drop the non-existent
   `~/.config/claude-code/settings.json`.
5. **`I_network.sh:32`** — `ufw status` needs root. Use
   `grep -q '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null || systemctl is-active --quiet ufw`;
   also accept `nftables`/`firewalld`/`iptables` active services before emitting
   "No firewall detected".
6. **`C_tokens.sh:48`** — `npm token list` prints a box table. Use
   `npm token list --json 2>/dev/null | jq length` when `HAS_JQ`, else
   `grep -cE '^│ [0-9a-f]{6}'`. Remove the "token age" promise from the module header
   or implement it from the `created` column.
7. **`G_compromise.sh:46`** — `gh repo list` defaults to 30. Use
   `gh repo list -L 1000 --json name --jq '.[].name'`. Add the Shai-Hulud indicators as
   `G.8` (repo names matching `Shai-Hulud|Sha1-Hulud`, local `setup_bun.js` /
   `bun_environment.js` under `node_modules`). Mark the indicator list with a date.
8. **`G_compromise.sh:34`** — anchor the shutdown pattern:
   `(^|[;&|[:space:]])(sudo[[:space:]]+)?(shutdown[[:space:]]+-[hP]|halt([[:space:]]|$)|poweroff)`
   and skip lines whose first non-space char is `#`.
9. **`G_compromise.sh:91`** — postinstall regex misses `node telemetry.js` (the cited
   payload). Add `telemetry\.js|setup_bun\.js|bun_environment\.js|\.sh\b` and remove the
   `head -200` cap (or emit INFO when capped).
10. **`B_ai_tools.sh:39-40,49`** — alias check: add `codex|opencode|copilot|goose|q`,
    the flags `--dangerously-bypass-approvals-and-sandbox|--full-auto|trust-all-tools|--yolo|-y\b`,
    and add the missing `-q` so the rc line is not printed to stdout.
11. **`F_sandbox.sh`** — WSL branch sets `in_container=1` (no `F.bare` alongside
    `F.wsl`); docker detection adds `/run/.containerenv` and `$container` (cgroup v2);
    `sudo -ln | grep -q NOPASSWD` → separate HIGH `F.sudo.nopasswd`, keep the cached
    finding only otherwise.
12. **`C_tokens.sh:16`** — do not read the raw GitHub token into a variable to inspect
    its prefix; use `gh auth token | cut -c1-11` or parse `gh auth status`.
13. **`E_backup.sh:49-54`** — replace `pushd` + `git remote` with
    `grep -c '^\[remote "' "$repo/.git/config"` (no git execution inside untrusted repos).

**Verification.** `bash tests/run.sh`; for every item one positive and one negative
fixture. For item 1 specifically: a fake `package.json` with `"axios": "1.14.1"` →
`N.1.npm.workspace` CRITICAL; with `"axios": "^1.14.0"` and a fake
`node_modules/axios/package.json` `"version": "1.14.1"` → the new resolved-version
finding; with `"axios": "1.13.0"` → nothing.

**Commit:** `Fix dead detections: compromised-version anchors, project-scope MCP, permissions schema, ufw, npm token, gh limit`

---

## T9 — Dev roots from `~/.claude.json`

**Why.** `DEV_SEARCH_PATHS` (`common.sh:169`) is seven guessed names; on the author's
machine it matches only `~/projects`, so modules K/L/M/N scan almost nothing and no
finding says so. Three modules also redefine their own lists (`A_credentials.sh:170`,
`B_ai_tools.sh:102`, `D_env_separation.sh:40`, `E_backup.sh:43`, `G_compromise.sh:84`,
`common.sh:141`).

**Changes.**

1. `common.sh`: build `DEV_SEARCH_PATHS` as:
   - `AUDIT_DEV_PATHS` (colon-separated env override) if set;
   - plus `jq -r '.projects | keys[]' ~/.claude.json` (dirs Claude Code actually ran in),
     filtered to existing directories, reduced to their parents when more than 3 siblings
     share a parent (so `~/main-projects/*` becomes `~/main-projects`);
   - plus `~/.codex`/`~/.gemini` project lists if they exist in a parseable form (skip if
     unsure; note in a comment);
   - plus the seven defaults;
   - deduplicated, existing only, hard cap 40 roots (emit INFO if capped).
2. Replace every module-local list with `"${DEV_SEARCH_PATHS[@]}"`; delete
   `find_nx_versions`'s private list.
3. New INFO finding `X.roots` emitted once by `run-audit.sh` (module id `X`, add to
   `ALL_MODULES` handling in `aggregate.sh` and the MD/HTML renderers): "Scanned N
   project roots: <list>". The action plan and HTML show it in the INFO section.
4. README/SKILL: document `AUDIT_DEV_PATHS` and the `~/.claude.json` derivation.

**Verification.** `tests/test_roots.sh`: fake home with `.claude.json` listing
`$HOME/work-a/p1`, `$HOME/work-a/p2`, `$HOME/work-a/p3`, `$HOME/work-a/p4`, `$HOME/solo`;
assert the computed array (source common.sh, `printf '%s\n' "${DEV_SEARCH_PATHS[@]}"`)
contains `$HOME/work-a` (collapsed) and `$HOME/solo`, and that a repo with a hook under
`$HOME/work-a/p3/.claude/settings.json` yields a K finding. `AUDIT_DEV_PATHS=$HOME/only`
→ only that root.

**Commit:** `Derive project roots from ~/.claude.json and report which roots were scanned`

---

## T10 — False positives and coverage gaps

**Changes (regex fixes, each with a positive + negative test string in
`tests/test_patterns.sh`):**

1. `D_env_separation.sh:47` — `(prod|rds\.amazonaws|cloudsql)` matches `products_dev`.
   Use `(\bprod(uction)?\b|rds\.amazonaws|cloudsql|\.supabase\.co|neon\.tech)` and skip
   `localhost|127\.0\.0\.1`.
2. `D_env_separation.sh:67` — gitignore regex misses `/.env` and `**/.env`. Use
   `^/?(\*\*/)?\.?env(\.\*|\*)?/?$|^\*\.env`.
3. `K_hooks.sh:139` / `L_skills.sh:38` — `you are now [a-z]+` → `you are now (a|an|the) `.
4. `K_hooks.sh:154` / `L_skills.sh:83` — netexec: `\|[[:space:]]*(ba|z|da)?sh\b`; delete
   the dead `--user-data-binary` alternative.
5. `K_hooks.sh:164` / `L_skills.sh:93` — bound the bypass pattern:
   `(skip|bypass|disable)[[:space:]]+(the[[:space:]]+)?(user[[:space:]]+)?(confirmation|approval|permission)`.
6. ZWBIDI byte class — remove U+200D (`\xe2\x80\x8d`, emoji ZWJ) from the class or
   require it not be preceded by an emoji lead byte; keep U+200B/U+200C/U+202A–E/U+2066–9.
7. `L_skills.sh:101` — enumerate skills as directories containing `SKILL.md`
   (`find "$d" -name SKILL.md -not -path '*/node_modules/*'`), not every subdirectory;
   scan `~/.claude/plugins/**/hooks/hooks.json` in module K.
8. `J_history_sessions.sh:74` — sort session files by mtime before `head -500` and emit
   INFO `J.3.capped` with `scanned/total` when capped (GNU: `find -printf '%T@ %p'`;
   BSD: `stat -f '%m %N'` loop; use the `$OS` branch).
9. Cline paths: `J_history_sessions.sh:171-182` and `M_mcp.sh:30-31` → explicit
   `<globalStorage>/saoudrizwan.claude-dev/{tasks/*/api_conversation_history.json,settings/cline_mcp_settings.json}`
   for Code, Code - Insiders, Cursor on Linux and macOS.
10. New paths (add to the relevant arrays, guarded by existence):
    - J: `~/.codex/sessions/**/*.jsonl`, `~/.codex/history.jsonl`,
      `~/.gemini/tmp/*/chats/*`, `~/.claude/file-history/**`, `~/.claude/shell-snapshots/*`.
    - M: `~/.codex/config.toml` (`^\[mcp_servers\.` + `command = "…"` via grep/sed),
      `~/.gemini/settings.json`, repo `.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`.
    - K: `~/.gemini/settings.json` hooks, `GEMINI.md`, `.claude/agents/*.md`,
      `.claude/commands/*.md`, `.github/copilot-instructions.md`.
    - A: `~/.netrc`, `~/.pgpass`, `~/.terraform.d/credentials.tfrc.json`, `~/.vault-token`,
      `~/.config/glab-cli/config.yml` (title already says GitHub / GitLab).
    - B.4 rules-file backdoor vector: HTML comments `<!-- … -->` and zero-width/bidi
      characters in `CLAUDE.md` / `.cursorrules` / `.windsurfrules` (reuse the ZWBIDI
      check from K so there is one implementation).
11. `A_credentials.sh:107` — count kube contexts via `kubectl config get-contexts -o name`
    when available, else count lines under the `contexts:` block only.
12. `B_ai_tools.sh:131` — Cursor `cursor.allowPrompt|autoApprove` are not settings keys;
    either query `state.vscdb` `ItemTable` for `yolo`/`autoRun` keys with `sqlite3`
    (guard `HAS_SQLITE`) or delete B.5. Decide by checking a real Cursor install if one
    exists on the machine; otherwise delete and note it in the commit body.

**Verification.** `tests/test_patterns.sh` sources the module files' regexes (extract
them into small named variables at the top of each module so tests can `grep -E` the
same string) and asserts each must-match / must-not-match string. Fixture-based tests
for 7, 9, 10 (create the files with fake tokens, assert the finding ids).

**Commit:** `Tighten prompt-injection and env regexes, enumerate skills by SKILL.md, add Codex/Gemini/Cline paths`

---

## T11 — Secrets counting and reuse of `secrets.sh`

**Why.** "Distinct classified secrets" counts inventory rows; `secrets.sh` dedupes only
within one source, so one key seen in `bash_history`, `history.jsonl` and a session is
counted three times in the headline and in the ÷15 score penalty. `B_ai_tools.sh:81` and
`M_mcp.sh:134` carry their own weaker key-name regex (`"token"`), missing
`"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_…"`.

**Changes.**

1. `aggregate.sh:38-43` and `html_report.sh:223-231`: count distinct fingerprints
   (`awk -F'|' '/^\| [A-Za-z]/{print $6}' | sort -u | wc -l`) and also report
   `secrets_occurrences` (rows) in JSON for transparency. Score uses the distinct count.
2. `secrets.sh:188-190`: replace `|` in cells with `/` instead of `\|` (all four awk
   parsers split on raw `|`).
3. B.3 and M.3 use `scan_classify_to_inventory "$cfg" "MCP config: $cfg"` (fingerprint
   output, full pattern set) plus a structural fallback
   `grep -qiE '"[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*"[[:space:]]*:[[:space:]]*"[^"]{8,}"'`.
   Remove B.3's duplicate of M's path list (M already covers a superset); B.3 keeps only
   the structural check on files M does not read, or is removed with a note.
4. `action_plan.sh:91` — delete the stray `print "" > "/dev/stderr"`.
5. `action_plan.sh:227` — `cut -c 1-200` is byte-based; use bash slicing
   `short=${remed%%$'\n'*}; short=${short:0:200}`.
6. `common.sh` — delete unused `count_matches`/`count_pattern_matches` (grep confirms no
   callers) or use them; delete `C_tokens.sh:36-39` no-op `if …; then :; fi` and
   `B_ai_tools.sh:30` append-after-consumer; `G_compromise.sh:69-71` → `file_mtime_unix`.

**Verification.** `tests/test_secrets_count.sh`: same fake token in `.bash_history` and in
a session JSONL → `summary.secrets_distinct == 1`, `summary.secrets_occurrences == 2`.
Fake `~/.claude.json` with `"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"<fake ghp_>"}` → M
plaintext-secret finding fires and the inventory has one `GitHub Classic PAT` row.

**Commit:** `Count distinct secrets by fingerprint and reuse secrets.sh in B and M`

---

## T12 — Score/grade consistency and docs sync

**Why.** README.md:93 and SKILL.md:81 print
`100 − 5×CRITICAL − 1.7×HIGH − 0.3×MEDIUM − 0.05×LOW − (distinct_secrets ÷ 20, capped 10)`
with no compound penalty; the code (`html_report.sh:45-50`) is
`100 − 5×C − 2.5×H − 0.3×M − 0.05×L − min(secrets/15, 15) − 10 if compound`, floor 0.
`compute_grade_class` (`html_report.sh:67-75`) uses 80/60/40/20 cut points while
`compute_grade` uses 90/80/70/60/50/30, so C is coloured like B and E like F. The badge
text at `:643-654` disagrees with the diagnosis line at `:203`. README/SKILL say "ASCII
skull on sub-50 scores"; code shows ☠ only below 30 and `.banner.skull` CSS is dead.
SKILL.md says "10 modules (A–J)", "two outputs", has Polish domain names
("Credentiale", "AI tooli config", "Separacja środowisk", "Detekcja Nx-style
kompromitacji", "Historia + AI sessions"), omits `secrets.sh`, `html_report.sh`,
`action_plan.sh`, `purge-secrets.sh`, `docs/usage-guide.md` from the file list, and
claims module J is opt-in with a confirmation that no script implements.

**Changes.**

1. One source of truth for the formula string: `SCORE_FORMULA_TEXT` in
   `html_report.sh` next to `compute_security_score`; `aggregate.sh` MD and the HTML use
   it. README and SKILL.md paste the same sentence (manual, but add a test that greps
   README/SKILL for `2.5×HIGH` and `÷15` so drift fails CI).
2. `compute_grade_class` maps from the grade letter: S,A→`grade-a`; B→`grade-b`;
   C,D→`grade-c`; E→`grade-d`; F→`grade-f`. Badge at `:643-654` uses the same cut points as
   `_html_diagnosis`. Delete dead `.banner.skull` CSS; docs say "☠ badge below 30".
3. `html_report.sh:158-159`: pass `sev` through `html_escape`; add `"`→`&quot;` to the
   awk escapers at `:155-157,173,186-188` (hardening, no XSS path today).
4. SKILL.md rewrite of the stale parts: 15 modules (A–N, P) + X roots, five artefacts,
   English domain names copied from README's module table, complete file list, and
   replace the "opt-in" sentence with: "Module J reads shell history and AI session
   transcripts. The script has no interactive gate; the agent must tell the user what
   will be read and offer `--modules` without J before running." Add a `--skip-sessions`
   flag to `run-audit.sh` that removes J from the list, and document it.
5. README: "four output files" (line ~42) → five; project tree adds `docs/`, `tests/`,
   `.github/`; Requirements adds bash ≥ 4; Development section from T1.
6. `docs/usage-guide.md`: re-read fully and correct anything the tasks above changed
   (paths, flags, formula, module list).

**Verification.**
```bash
bash tests/run.sh                       # includes the new docs-drift test
grep -n '1.7×HIGH\|÷ 20\|sessions/\|10 modules\|two outputs\|Credentiale' README.md SKILL.md docs/*.md   # no hits
bash scripts/run-audit.sh --help        # lists --skip-sessions
```

**Commit:** `Align score formula, grade colours and docs with the implementation`

---

## T13 — Final full run, CHANGELOG, push

1. `bash tests/run.sh` — all green. `shellcheck -S warning` on all scripts — clean.
2. Real-machine smoke test (the only run against the real home):
   `bash scripts/run-audit.sh --no-open --output /tmp/aaa-final` then
   `jq '.score, .grade, .summary, .modules_run' /tmp/aaa-final/audit-report.json`,
   open nothing, inspect `audit-report.md` for `[REDACTED]`/`[untrusted content]`
   rendering, confirm `~/.ai-agent-audit` was not modified (mtime), then
   `rm -rf /tmp/aaa-final`.
3. `grep -rn 'TODO\|FIXME' scripts/ tests/` — none introduced by this work.
4. Add `CHANGELOG.md` with a `2026-10` section: one line per task, user-facing wording
   (what changed for someone running the tool), and a "Breaking" note: `--output` now
   actually isolates the run; `purge-secrets.sh` redacts in place by default
   (`--delete-lines` for old behaviour); bash ≥ 4 required.
5. Mark this plan done: add `Status: completed <date>, see CHANGELOG.md` under the title
   of this file.
6. `git log --oneline origin/main..HEAD` — 13 commits, none with an AI footer
   (`git log origin/main..HEAD --format=%B | grep -i 'co-authored\|generated with'` → empty).
7. `git push origin main`. If rejected, do not force; report the exact error.
8. Final report to the user: score before/after on this machine (before = the one in
   `~/.ai-agent-audit/audit-report.json` from the previous run, after = step 2), list of
   commits, CI link, anything skipped with the reason.

**Commit:** `Add CHANGELOG for the October 2026 hardening round`
