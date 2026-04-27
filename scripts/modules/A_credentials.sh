#!/usr/bin/env bash
# Module A: Credentials audit
# Scans well-known credential storage locations for presence, exposure, and weak protection.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

MODULE="A"
log "$MODULE" "Starting credentials audit..."

# Reset module findings
> "$FINDINGS_DIR/$MODULE.jsonl"

# ---------- A.1: SSH keys ----------
SSH_DIR="$HOME/.ssh"
if [[ -d "$SSH_DIR" ]]; then
  # Find private keys (heuristic: files without .pub extension that look like keys)
  while IFS= read -r -d '' key; do
    [[ -z "$key" ]] && continue
    base=$(basename "$key")
    # Skip known non-key files
    case "$base" in
      known_hosts*|config|authorized_keys|*.pub|environment) continue ;;
    esac
    # Verify it's a private key
    head -n 1 "$key" 2>/dev/null | grep -qE 'BEGIN.*PRIVATE KEY' || continue

    # Check perms
    perms=$(file_perm_octal "$key")
    if [[ -n "$perms" && "$perms" != "600" && "$perms" != "400" ]]; then
      emit_finding "$MODULE" "HIGH" "A.1.perm" \
        "SSH private key has loose permissions: $key" \
        "Permissions are $perms; should be 600 or 400." \
        "Run: chmod 600 \"$key\"" \
        "Generic key hygiene"
    fi

    # Check passphrase
    if ssh_key_has_passphrase "$key"; then
      emit_finding "$MODULE" "INFO" "A.1.pass" \
        "SSH private key is passphrase-protected: $key" \
        "Has passphrase (good)." "" ""
    else
      rc=$?
      if [[ $rc -eq 1 ]]; then
        emit_finding "$MODULE" "CRITICAL" "A.1.nopass" \
          "SSH private key has NO passphrase: $key" \
          "Key can be used by any process running as this user, including AI agents that read \$HOME." \
          "Add a passphrase: ssh-keygen -p -f \"$key\". Better: rotate to a new key with passphrase, distribute pubkey, retire the old one." \
          "Nx s1ngularity attack (Aug 2025) — SSH keys harvested from ~/.ssh by AI CLI invoked with --dangerously-skip-permissions"
      fi
    fi
  done < <(find "$SSH_DIR" -maxdepth 1 -type f -print0 2>/dev/null)

  # Loaded ssh-agent keys (currently usable without passphrase)
  if has ssh-add; then
    loaded=$(ssh-add -l 2>/dev/null | grep -v 'no identities' | wc -l | tr -d ' ')
    if [[ "$loaded" -gt 0 ]]; then
      emit_finding "$MODULE" "HIGH" "A.1.agent" \
        "ssh-agent has $loaded key(s) loaded" \
        "Any process running as this user — including AI agents with shell access — can use these keys to SSH anywhere they grant access, with no passphrase prompt." \
        "Audit which keys are loaded: ssh-add -l. Remove production keys: ssh-add -d <key>. Consider keychain timeout: ssh-add -t 3600 <key>." \
        "PocketOS-style scenario — agent uses pre-authenticated SSH session"
    fi
  fi
else
  emit_finding "$MODULE" "INFO" "A.1.none" "No ~/.ssh directory" "" "" ""
fi

# ---------- A.2: Cloud credentials ----------
# AWS
if [[ -f "$HOME/.aws/credentials" ]]; then
  perms=$(file_perm_octal "$HOME/.aws/credentials")
  profile_count=$(grep -cE '^\[' "$HOME/.aws/credentials" 2>/dev/null || echo 0)

  # Check for long-lived AKIA keys (vs SSO/temporary STS)
  if grep -qE 'aws_access_key_id\s*=\s*AKIA' "$HOME/.aws/credentials" 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "A.2.aws.longlived" \
      "AWS long-lived access key (AKIA) found in ~/.aws/credentials" \
      "$profile_count profile(s) total. AKIA keys never expire. Compare to SSO/IAM Identity Center which rotates automatically." \
      "Migrate to AWS SSO: aws configure sso. Then delete the IAM access key in IAM console." \
      "Nx s1ngularity — AWS credentials harvested from ~/.aws/"
  fi

  if [[ -n "$perms" && "$perms" != "600" ]]; then
    emit_finding "$MODULE" "MEDIUM" "A.2.aws.perm" \
      "~/.aws/credentials has loose permissions ($perms)" \
      "" "chmod 600 ~/.aws/credentials" ""
  fi
fi

# GCP
for f in "$HOME/.config/gcloud/application_default_credentials.json" "$HOME/.config/gcloud/legacy_credentials"; do
  if [[ -e "$f" ]]; then
    emit_finding "$MODULE" "MEDIUM" "A.2.gcp" \
      "GCP credentials present: $f" \
      "Application Default Credentials are readable by any process as this user." \
      "If unused: gcloud auth application-default revoke. Otherwise prefer short-lived service account impersonation." \
      ""
    break
  fi
done

# Kubernetes
if [[ -f "$HOME/.kube/config" ]]; then
  ctx_count=$(grep -cE '^\s*name:' "$HOME/.kube/config" 2>/dev/null || echo 0)
  emit_finding "$MODULE" "MEDIUM" "A.2.k8s" \
    "Kubernetes config present (~/.kube/config) with $ctx_count context entries" \
    "kubectl bound to whatever clusters are listed. Agent with shell access can run kubectl against any of them." \
    "Audit: kubectl config get-contexts. Remove unused contexts. For prod clusters use short-lived OIDC tokens." \
    ""
fi

# Azure
if [[ -d "$HOME/.azure" ]]; then
  emit_finding "$MODULE" "MEDIUM" "A.2.azure" \
    "Azure CLI credentials present (~/.azure/)" \
    "" "Audit: az account list. Sign out unused: az account clear" ""
fi

# ---------- A.3: Package manager tokens ----------
# npm
if [[ -f "$HOME/.npmrc" ]]; then
  if grep -qE '_authToken|_password|//.*:_auth' "$HOME/.npmrc" 2>/dev/null; then
    perms=$(file_perm_octal "$HOME/.npmrc")
    emit_finding "$MODULE" "HIGH" "A.3.npm" \
      "npm auth token in ~/.npmrc (perms: $perms)" \
      "Token may have publish rights to packages. Compromise = supply chain attack capability (see Nx case)." \
      "List tokens: npm token list. Rotate via npm.com → Tokens. Use granular tokens scoped to specific packages." \
      "Nx s1ngularity — npm token from .npmrc was the vector for malicious package publish"
  fi
fi

# Cargo, PyPI
[[ -f "$HOME/.cargo/credentials.toml" ]] && emit_finding "$MODULE" "MEDIUM" "A.3.cargo" "Cargo credentials present" "crates.io publish token" "Rotate at crates.io if unused" ""
[[ -f "$HOME/.pypirc" ]] && emit_finding "$MODULE" "MEDIUM" "A.3.pypi" "PyPI credentials present (~/.pypirc)" "PyPI publish token" "Use API tokens scoped per project at pypi.org" ""

# Docker
if [[ -f "$HOME/.docker/config.json" ]]; then
  if grep -q '"auth"' "$HOME/.docker/config.json" 2>/dev/null; then
    emit_finding "$MODULE" "MEDIUM" "A.3.docker" \
      "Docker registry auth in ~/.docker/config.json" \
      "Embedded base64 of registry credentials." \
      "Use credential helpers (osxkeychain, secretservice, pass) instead of plaintext auths." ""
  fi
fi

# ---------- A.4: GitHub / GitLab CLI tokens ----------
if [[ -f "$HOME/.config/gh/hosts.yml" ]]; then
  if grep -q 'oauth_token' "$HOME/.config/gh/hosts.yml" 2>/dev/null; then
    emit_finding "$MODULE" "HIGH" "A.4.gh" \
      "GitHub CLI OAuth token stored at ~/.config/gh/hosts.yml" \
      "Token grants gh CLI full access to user's repos. Cross-repo prompt-injection (Invariant Labs case) can abuse this." \
      "Check scopes: gh auth status. Refresh with minimum scope: gh auth refresh -s repo,read:org. Consider fine-grained PAT instead." \
      "GitHub MCP cross-repo data leak (Invariant Labs, May 2025); Nx s1ngularity used gh tokens"
  fi
fi

# git-credentials (plaintext URLs with passwords)
if [[ -f "$HOME/.git-credentials" ]]; then
  emit_finding "$MODULE" "HIGH" "A.4.git" \
    "~/.git-credentials present (plaintext)" \
    "git credential.helper=store writes URLs with username:password in plaintext." \
    "Switch to system keychain: macOS: git config --global credential.helper osxkeychain. Linux: credential-libsecret." ""
fi

# ---------- A.5: .env files in workspace ----------
# Search common dev paths for .env files (limited depth, exclude node_modules)
ENV_PATHS=("$HOME/Projects" "$HOME/projects" "$HOME/dev" "$HOME/code" "$HOME/work" "$HOME/repos" "$HOME/src")
env_count=0
env_examples=""
for p in "${ENV_PATHS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    env_count=$((env_count+1))
    [[ $env_count -le 3 ]] && env_examples="$env_examples$f\n"
  done < <(find "$p" -maxdepth 4 -type f \( -name '.env' -o -name '.env.local' -o -name '.env.production' -o -name '.env.prod' \) -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
done

if [[ $env_count -gt 0 ]]; then
  emit_finding "$MODULE" "HIGH" "A.5.env" \
    "$env_count .env file(s) in dev workspace" \
    "First examples:\n$env_examples" \
    "Verify each is in .gitignore. For production secrets use a vault (1Password, Doppler, AWS Secrets Manager, Infisical). Never commit .env." \
    "PocketOS — agent found token in unrelated file and used it to delete production"
fi

# ---------- A.6: GPG ----------
if [[ -d "$HOME/.gnupg" ]] && has gpg; then
  key_count=$(gpg --list-secret-keys --with-colons 2>/dev/null | grep -c '^sec')
  if [[ $key_count -gt 0 ]]; then
    emit_finding "$MODULE" "INFO" "A.6.gpg" \
      "$key_count GPG secret key(s) present" \
      "GPG keys can sign commits, npm publish, etc." \
      "Audit: gpg --list-secret-keys. Keys without passphrase are equivalent to SSH keys without passphrase." \
      ""
  fi
fi

# ---------- A.7: GitHub CLI scope check ----------
if [[ "$HAS_GH" -eq 1 ]]; then
  scopes=$(gh auth status 2>&1 | grep -i 'scopes' | head -1 || true)
  if [[ -n "$scopes" ]]; then
    if echo "$scopes" | grep -qE 'admin:|delete_repo|workflow|write:packages'; then
      emit_finding "$MODULE" "HIGH" "A.7.ghscope" \
        "GitHub CLI token has powerful scopes" \
        "Scopes: $scopes" \
        "Refresh with minimum needed scopes: gh auth refresh -s repo,read:org. For destructive ops use a separate token loaded only when needed." \
        "Comment and Control attack (April 2026) — GitHub Action posted secrets via PR injection"
    fi
  fi
fi

# ---------- A.8: Crypto wallets ----------
for path in "$HOME/.ethereum/keystore" "$HOME/.config/Ledger Live" "$HOME/.metamask"; do
  if [[ -d "$path" ]]; then
    emit_finding "$MODULE" "HIGH" "A.8.crypto" \
      "Crypto wallet directory: $path" \
      "Wallet artifacts on disk are a known target." \
      "Move to hardware wallet for storage. If keystore exists, ensure passphrase is strong." \
      "Nx s1ngularity attack explicitly targeted crypto wallets"
    break
  fi
done

log "$MODULE" "done — $(wc -l < "$FINDINGS_DIR/$MODULE.jsonl" | tr -d ' ') findings"
