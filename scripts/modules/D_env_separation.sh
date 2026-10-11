#!/usr/bin/env bash
# Module D: Environment separation — dev/prod profiles, SSH config, .gitignore hygiene
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="D"
log "$MODULE" "Starting environment separation audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# AWS profiles — count distinct profiles
if [[ -f "$HOME/.aws/config" ]]; then
  profile_count=$(grep -cE '^\[profile' "$HOME/.aws/config" 2>/dev/null) || profile_count=0
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
  prod_hosts=$(grep -ciE '^Host\s+(prod|production)' "$HOME/.ssh/config" 2>/dev/null) || prod_hosts=0
  total_hosts=$(grep -cE '^Host\s+' "$HOME/.ssh/config" 2>/dev/null) || total_hosts=0
  if [[ "$total_hosts" -gt 0 ]]; then
    emit_finding "$MODULE" "INFO" "D.ssh" \
      "SSH config has $total_hosts host(s), $prod_hosts marked as prod" \
      "" "Use clear naming: prod-*, staging-*, dev-* to make agent decisions explicit." ""
  fi
fi

# Active workspace .env analysis — does it point to production?
PROD_DB_RE='DATABASE_URL[^=]*=.*((^|[^A-Za-z0-9])prod(uction)?([^A-Za-z0-9]|$)|rds\.amazonaws|cloudsql|\.supabase\.co|neon\.tech)'
# .gitignore lines that ignore .env: ".env", "/.env", "**/.env", ".env*", ".env.*", "*.env"
ENV_IGNORE_RE='^/?(\*\*/)?\.env(\.\*|\*)?/?[[:space:]]*$|^\*\.env[[:space:]]*$'
suspicious_envs=0
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    # DATABASE_URL that names prod/production as a word or a managed cloud DB host, and is
    # not a local URL ("products_dev" or "reproduce" are not prod).
    if grep -E "$PROD_DB_RE" "$f" 2>/dev/null | grep -qvE 'localhost|127\.0\.0\.1|host\.docker\.internal'; then
      suspicious_envs=$((suspicious_envs+1))
      [[ $suspicious_envs -le 3 ]] && \
        emit_finding "$MODULE" "HIGH" "D.env.prod" \
          "Possible production DATABASE_URL in dev workspace: $f" \
          "" \
          "Verify which env this is. Production credentials should never sit in a dev workspace .env file. Use a vault." \
          "PocketOS — agent connected to prod DB because credentials were locally accessible"
    fi
  done < <(dev_find "$p" 4 -type f \( -name '.env' -o -name '.env.local' -o -name '.env.production' \))
done

# .gitignore hygiene — sample check
gitignored=0
not_gitignored=0
for p in "${DEV_SEARCH_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    if [[ -f "$repo/.env" ]]; then
      if [[ -f "$repo/.gitignore" ]] && grep -qE "$ENV_IGNORE_RE" "$repo/.gitignore" 2>/dev/null; then
        gitignored=$((gitignored+1))
      else
        not_gitignored=$((not_gitignored+1))
        [[ $not_gitignored -le 3 ]] && \
          emit_finding "$MODULE" "HIGH" "D.gitignore" \
            ".env not in .gitignore: $repo" \
            "" "Add .env, .env.* to .gitignore immediately. Check git log to ensure it was never committed." ""
      fi
    fi
  done < <(find "$p" -maxdepth 3 -name node_modules -prune -o -type d -name '.git' -prune -print 2>/dev/null | sed 's#/\.git$##')
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
