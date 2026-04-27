#!/usr/bin/env bash
# Module C: Token scope audit — token age, scope, type
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="C"
log "$MODULE" "Starting token scope audit..."
> "$FINDINGS_DIR/$MODULE.jsonl"

# GitHub
if [[ "$HAS_GH" -eq 1 ]]; then
  status=$(gh auth status 2>&1 || true)
  if echo "$status" | grep -q 'Logged in'; then
    # Determine token type from prefix (ghp_ classic, github_pat_ fine-grained, gho_ OAuth)
    token=$(gh auth token 2>/dev/null || echo "")
    case "$token" in
      ghp_*)
        emit_finding "$MODULE" "HIGH" "C.gh.classic" \
          "GitHub classic Personal Access Token in use" \
          "Classic PATs grant org-wide access by scope. Cannot be limited per-repo." \
          "Migrate to fine-grained PAT: github.com/settings/tokens?type=beta. Scope to specific repos." \
          "Comment and Control attack — runtime, not model, was the blast radius"
        ;;
      github_pat_*)
        emit_finding "$MODULE" "INFO" "C.gh.fg" "GitHub fine-grained PAT in use (good)" "" "" ""
        ;;
      gho_*)
        emit_finding "$MODULE" "INFO" "C.gh.oauth" "GitHub OAuth token in use" "" "" ""
        ;;
    esac
  fi
fi

# AWS — detect long-lived vs SSO
if [[ -f "$HOME/.aws/credentials" ]]; then
  if grep -qE 'aws_access_key_id\s*=\s*AKIA' "$HOME/.aws/credentials" 2>/dev/null; then
    : # already flagged by Module A.2
  fi
  # SSO config
  if [[ -f "$HOME/.aws/config" ]] && grep -qE 'sso_session|sso_start_url' "$HOME/.aws/config" 2>/dev/null; then
    emit_finding "$MODULE" "INFO" "C.aws.sso" "AWS SSO configured (good — short-lived credentials)" "" "" ""
  fi
fi

# npm token list
if [[ "$HAS_NPM" -eq 1 ]] && npm whoami >/dev/null 2>&1; then
  tokens=$(npm token list 2>/dev/null | grep -cE '^Token' || echo 0)
  if [[ "$tokens" -gt 0 ]]; then
    emit_finding "$MODULE" "MEDIUM" "C.npm" \
      "$tokens npm token(s) for current account" \
      "Inspect: npm token list. Old tokens still grant access until revoked." \
      "Delete unused: npm token revoke <id>. Use granular tokens scoped to packages." ""
  fi
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
