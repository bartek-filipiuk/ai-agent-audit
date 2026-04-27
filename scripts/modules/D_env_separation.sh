#!/usr/bin/env bash
# Module D: Environment separation — dev/prod profiles, SSH config, .gitignore hygiene
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="D"
log "$MODULE" "Starting environment separation audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# AWS profiles — count distinct profiles
if [[ -f "$HOME/.aws/config" ]]; then
  profile_count=$(grep -cE '^\[profile' "$HOME/.aws/config" 2>/dev/null || echo 0)
  if [[ "$profile_count" -le 1 ]]; then
    emit_finding "$MODULE" "MEDIUM" "D.aws.single" \
      "AWS has only $profile_count profile(s)" \
      "No separation between dev and prod environments." \
      "Create separate profiles: aws configure --profile dev / --profile prod. Use AWS_PROFILE env var to switch." \
      "Grigorev/Claude Code AWS — prod env destroyed because no separation"
  else
    # Check for prod-named profile alongside dev
    if grep -qE '^\[profile (prod|production)' "$HOME/.aws/config" 2>/dev/null; then
      emit_finding "$MODULE" "INFO" "D.aws.prod" "AWS prod profile exists (good — distinct from dev)" "" "" ""
    fi
  fi
fi

# SSH config — look for prod-* aliases
if [[ -f "$HOME/.ssh/config" ]]; then
  prod_hosts=$(grep -ciE '^Host\s+(prod|production)' "$HOME/.ssh/config" 2>/dev/null || echo 0)
  total_hosts=$(grep -cE '^Host\s+' "$HOME/.ssh/config" 2>/dev/null || echo 0)
  if [[ "$total_hosts" -gt 0 ]]; then
    emit_finding "$MODULE" "INFO" "D.ssh" \
      "SSH config has $total_hosts host(s), $prod_hosts marked as prod" \
      "" "Use clear naming: prod-*, staging-*, dev-* to make agent decisions explicit." ""
  fi
fi

# Active workspace .env analysis — does it point to production?
ENV_PATHS=("$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work")
suspicious_envs=0
for p in "${ENV_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    # Heuristic: DATABASE_URL pointing to non-localhost AND containing 'prod' OR rds.amazonaws.com
    if grep -qE 'DATABASE_URL.*=.*(prod|rds\.amazonaws|cloudsql)' "$f" 2>/dev/null; then
      suspicious_envs=$((suspicious_envs+1))
      [[ $suspicious_envs -le 3 ]] && \
        emit_finding "$MODULE" "HIGH" "D.env.prod" \
          "Possible production DATABASE_URL in dev workspace: $f" \
          "" \
          "Verify which env this is. Production credentials should never sit in a dev workspace .env file. Use a vault." \
          "PocketOS — agent connected to prod DB because credentials were locally accessible"
    fi
  done < <(find "$p" -maxdepth 4 -type f \( -name '.env' -o -name '.env.local' -o -name '.env.production' \) -not -path '*/node_modules/*' 2>/dev/null)
done

# .gitignore hygiene — sample check
gitignored=0
not_gitignored=0
for p in "${ENV_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    if [[ -f "$repo/.env" ]]; then
      if [[ -f "$repo/.gitignore" ]] && grep -qE '^\.?env|^\*\.env' "$repo/.gitignore" 2>/dev/null; then
        gitignored=$((gitignored+1))
      else
        not_gitignored=$((not_gitignored+1))
        [[ $not_gitignored -le 3 ]] && \
          emit_finding "$MODULE" "HIGH" "D.gitignore" \
            ".env not in .gitignore: $repo" \
            "" "Add .env, .env.* to .gitignore immediately. Check git log to ensure it was never committed." ""
      fi
    fi
  done < <(find "$p" -maxdepth 3 -type d -name '.git' -exec dirname {} \; 2>/dev/null)
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
