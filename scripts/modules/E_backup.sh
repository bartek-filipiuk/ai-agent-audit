#!/usr/bin/env bash
# Module E: Backup hygiene
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="E"
log "$MODULE" "Starting backup hygiene audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

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
  if tmutil status 2>/dev/null | grep -q 'BackupPhase\|Running'; then
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
ENV_PATHS=("$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work")
single_remote_repos=0
for p in "${ENV_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    pushd "$repo" >/dev/null 2>&1 || continue
    remote_count=$(git remote 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$remote_count" -le 1 ]]; then
      single_remote_repos=$((single_remote_repos+1))
    fi
    popd >/dev/null 2>&1
  done < <(find "$p" -maxdepth 3 -type d -name '.git' -exec dirname {} \; 2>/dev/null)
done

if [[ "$single_remote_repos" -gt 5 ]]; then
  emit_finding "$MODULE" "LOW" "E.singleremote" \
    "$single_remote_repos repo(s) have only one git remote" \
    "Single point of failure for code." \
    "Consider mirroring critical work to a second remote (Codeberg, GitLab) — 'git remote add mirror …'." ""
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
