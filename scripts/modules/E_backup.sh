#!/usr/bin/env bash
# Module E: Backup hygiene
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="E"
log "$MODULE" "Starting backup hygiene audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# Detect backup tools
backup_tool_found=0
for cmd in restic borg duplicacy rclone tarsnap kopia; do
  if has "$cmd"; then
    emit_finding "$MODULE" "INFO" "E.tool" "$cmd installed (backup tool present)" "" "" ""
    backup_tool_found=1
  fi
done

# macOS TimeMachine
if [[ "$OS" == "macos" ]]; then
  # Idle output contains "Running = 0;", so match only an active backup.
  if tmutil status 2>/dev/null | grep -qE 'Running = 1;|BackupPhase'; then
    emit_finding "$MODULE" "INFO" "E.timemachine" "TimeMachine appears active" "" "" ""
    backup_tool_found=1
  elif has tmutil; then
    last=$(tmutil latestbackup 2>/dev/null || echo "")
    if [[ -n "$last" ]]; then
      emit_finding "$MODULE" "INFO" "E.timemachine.last" "TimeMachine last backup: $last" "" "" ""
      backup_tool_found=1
    fi
  fi
fi

if [[ "$backup_tool_found" -eq 0 ]]; then
  emit_finding "$MODULE" "MEDIUM" "E.nobackup" \
    "No backup tool detected" \
    "Found no restic/borg/TimeMachine/etc. If primary copy of work is only on this machine, single point of failure." \
    "Set up at least one off-site backup: TimeMachine to NAS, restic to B2, borg to a remote, or comparable. Test restore." \
    "PocketOS — 'backups' were in the same blast radius as production data"
fi

# Check git remotes diversity for projects
single_remote_repos=0
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    # Read .git/config as a file: no git process inside a possibly untrusted repo.
    remote_count=$(grep -c '^\[remote "' "$repo/.git/config" 2>/dev/null) || remote_count=0
    if [[ "$remote_count" -le 1 ]]; then
      single_remote_repos=$((single_remote_repos+1))
    fi
  done < <(find "$p" -maxdepth 3 -name node_modules -prune -o -type d -name '.git' -prune -print 2>/dev/null | sed 's#/\.git$##')
done

if [[ "$single_remote_repos" -gt 5 ]]; then
  emit_finding "$MODULE" "LOW" "E.singleremote" \
    "$single_remote_repos repo(s) have only one git remote" \
    "Single point of failure for code." \
    "Consider mirroring critical work to a second remote (Codeberg, GitLab) — 'git remote add mirror …'." ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
