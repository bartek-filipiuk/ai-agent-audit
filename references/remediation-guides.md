# Remediation Guides

Vendor-specific fix steps. Reference when guiding users through fixes for specific findings.

## SSH key without passphrase (A.1.nopass — CRITICAL)

**Add passphrase to existing key:**
```bash
ssh-keygen -p -f ~/.ssh/id_ed25519
```

**Better — rotate the key:**
```bash
# 1. Generate new key with passphrase
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -C "your@email"

# 2. Distribute new pubkey
ssh-copy-id -i ~/.ssh/id_ed25519_new.pub user@host
# Or for GitHub: gh ssh-key add ~/.ssh/id_ed25519_new.pub --title "New key 2026"

# 3. Test
ssh -i ~/.ssh/id_ed25519_new user@host

# 4. Once verified, retire old key
mv ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.old
mv ~/.ssh/id_ed25519_new ~/.ssh/id_ed25519
```

**If keys are loaded in ssh-agent:**
```bash
ssh-add -D                    # remove all
ssh-add -t 3600 ~/.ssh/key    # load with 1h timeout
```

## AWS long-lived AKIA keys (A.2.aws.longlived — HIGH)

**Migrate to AWS SSO:**
```bash
# 1. Configure SSO
aws configure sso
# Follow prompts to set start URL, region, profile name

# 2. Test
aws sso login --profile myprofile
aws s3 ls --profile myprofile

# 3. Update workflow to use --profile or AWS_PROFILE env var

# 4. In AWS Console → IAM → Users → your user → Security credentials
#    → Delete the access key (or mark inactive first to verify nothing breaks)
```

## GitHub classic PAT (C.gh.classic — HIGH)

**Migrate to fine-grained PAT:**
1. Go to github.com/settings/tokens?type=beta
2. Click "Generate new token"
3. Set expiration (max 1 year — pick shorter)
4. Select specific repositories (NOT "All repositories")
5. Set permissions per resource (Contents: Read, Issues: Write, etc.)
6. Replace in gh CLI: `gh auth refresh` or `gh auth login --with-token < token.txt`

## Compromised Nx version (G.1.nxversion — CRITICAL)

**Full incident response:**

```bash
# 1. STOP — don't run npm install or any agent in this directory.

# 2. Treat all credentials as compromised. Rotate immediately:

# GitHub:
gh auth status                                # see what's authenticated
# Then in github.com/settings/tokens, revoke all PATs
# In github.com/settings/applications, revoke all OAuth apps
# Re-create with minimum scope

# npm:
npm token list
npm token revoke <id>                         # for each
# Generate new at npmjs.com/settings/<user>/tokens

# AWS:
# IAM Console → Users → Security credentials → Delete access keys
# Switch to SSO

# SSH:
# Rotate every key in ~/.ssh/

# Crypto wallets:
# Move funds to fresh wallet generated on uncompromised device

# 3. Check GitHub for s1ngularity-repository on your account:
gh repo list --json name,visibility | grep s1ngularity

# 4. If found, those repos contain your encoded credentials. Make private/delete:
gh repo delete <owner>/<repo> --yes

# 5. Inspect shell init for shutdown sabotage:
grep -nE 'shutdown|halt' ~/.bashrc ~/.zshrc

# 6. Clean install Nx with safe version:
rm -rf node_modules package-lock.json
npm install nx@latest --save-dev

# 7. Audit GitHub audit log for the attack window:
# github.com/settings/security-log
```

Reference advisory: https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c

## .env in dev workspace (A.5.env — HIGH)

**Move secrets to a vault:**

Option 1 — 1Password CLI:
```bash
# Reference secret in code
DATABASE_URL=$(op read "op://Engineering/myapp-db/url")
```

Option 2 — direnv with system keychain:
```bash
# .envrc (gitignored)
export DATABASE_URL=$(security find-generic-password -s myapp-db -w)
```

Option 3 — Doppler / Infisical for team:
```bash
doppler run -- npm start
```

**Always:**
```bash
# Add to .gitignore (every project)
echo -e ".env\n.env.*\n!.env.example" >> .gitignore

# Verify never committed
git log --all --full-history -- .env
```

## MCP config with plaintext secrets (B.3.secrets — HIGH)

**Use env-var injection at runtime:**

Bad:
```json
{
  "mcpServers": {
    "github": {
      "env": { "GITHUB_TOKEN": "ghp_real_token_here" }
    }
  }
}
```

Good:
```json
{
  "mcpServers": {
    "github": {
      "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }
    }
  }
}
```

Then load via launcher script that pulls from 1Password / vault.

## Shutdown injection in shell init (G.2.shutdown — CRITICAL)

**This is a confirmed compromise indicator. Treat machine as compromised:**

```bash
# 1. Comment out the line (don't delete yet — may need for forensics)
sed -i.bak 's|^sudo shutdown.*|# COMPROMISED: &|' ~/.zshrc

# 2. Open new terminal, verify it doesn't crash

# 3. Compare full file to known-good (if you have dotfiles in git):
cd ~/dotfiles && git diff zshrc

# 4. Run through full Nx remediation above (rotate everything)
```

## Secrets in shell history (J.leak — HIGH)

**Clear and rotate:**
```bash
# Identify which file
grep -nE 'AKIA|ghp_|sk-|xox' ~/.bash_history ~/.zsh_history

# Note the credentials, ROTATE them in the respective vendor

# Clear history
history -c                  # current session
> ~/.bash_history           # bash file
> ~/.zsh_history            # zsh file

# Prevent recurrence
echo 'export HISTCONTROL=ignorespace' >> ~/.bashrc
# Now any command starting with space won't be saved
```

For zsh, add to `.zshrc`:
```
setopt HIST_IGNORE_SPACE
```

## Cursor / Claude Code chat history with secrets (J.3.cursor.leak / J.2.cc.leak — HIGH)

**Claude Code:**
```bash
# Find sessions with secrets
grep -lE 'AKIA|ghp_|sk-' ~/.claude/projects/*/sessions/*.jsonl

# Delete those sessions
rm <path-to-jsonl>

# Clear global history
> ~/.claude/history.jsonl
```

**Cursor (requires sqlite3):**
```bash
# Find affected workspace DBs
for db in ~/Library/Application\ Support/Cursor/User/workspaceStorage/*/state.vscdb; do
  if sqlite3 "$db" "SELECT value FROM ItemTable WHERE key='aiService.prompts';" 2>/dev/null | grep -qE 'AKIA|ghp_|sk-'; then
    echo "$db"
  fi
done

# Easiest fix: close Cursor, delete the workspaceStorage folder for affected workspace
# Cursor will recreate it on next open (you lose chat history for that workspace)
```

**Going forward:** never paste credentials into AI chat. Use `[REDACTED]` placeholders or reference env vars: `"the value of $DATABASE_URL"`.

## docker group membership (F.docker — HIGH)

**Remove if unused:**
```bash
sudo gpasswd -d $USER docker
# Log out and log back in
```

**If you need Docker, use rootless:**
```bash
# Linux: install docker-rootless-extras, configure
dockerd-rootless-setuptool.sh install
# Use ~/.docker context instead of root daemon
```

## Active 1Password / Bitwarden session (H.1p / H.bw — MEDIUM)

**Enable biometric prompt per call:**

1Password CLI:
- Open 1Password app → Settings → Developer → "Connect with 1Password CLI"
- Now `op` will require Touch ID / system password per command.

Bitwarden:
```bash
bw lock      # lock now
# Use BW_SESSION env var only when actively using
```
