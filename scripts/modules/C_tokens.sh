#!/usr/bin/env bash
# Module C: Token scope audit — token type (GitHub), SSO vs long-lived (AWS), npm token count
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="C"
log "$MODULE" "Starting token scope audit..."
: > "$FINDINGS_DIR/$MODULE.jsonl"

# GitHub
if [[ "$HAS_GH" -eq 1 ]]; then
  status=$(gh auth status 2>&1 || true)
  if echo "$status" | grep -q 'Logged in'; then
    # Token type from its prefix (ghp_ classic, github_pat_ fine-grained, gho_ OAuth).
    # Only the first 11 characters ever reach a variable.
    token_prefix=$(gh auth token 2>/dev/null | cut -c1-11)
    case "$token_prefix" in
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
  # SSO config
  if [[ -f "$HOME/.aws/config" ]] && grep -qE 'sso_session|sso_start_url' "$HOME/.aws/config" 2>/dev/null; then
    emit_finding "$MODULE" "INFO" "C.aws.sso" "AWS SSO configured (good — short-lived credentials)" "" "" ""
  fi
fi

# npm token list
if [[ "$HAS_NPM" -eq 1 ]] && npm whoami >/dev/null 2>&1; then
  # The human-readable list is a box-drawn table; count via --json.
  if [[ "$HAS_JQ" -eq 1 ]]; then
    tokens=$(npm token list --json 2>/dev/null | jq 'length' 2>/dev/null) || tokens=0
  else
    tokens=$(npm token list 2>/dev/null | grep -cE '^│ [0-9a-f]{6}') || tokens=0
  fi
  [[ "$tokens" =~ ^[0-9]+$ ]] || tokens=0
  if [[ "$tokens" -gt 0 ]]; then
    emit_finding "$MODULE" "MEDIUM" "C.npm" \
      "$tokens npm token(s) for current account" \
      "Inspect: npm token list. Old tokens still grant access until revoked." \
      "Delete unused: npm token revoke <id>. Use granular tokens scoped to packages." ""
  fi
fi

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
