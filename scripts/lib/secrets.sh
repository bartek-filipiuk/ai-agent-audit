#!/usr/bin/env bash
# Secrets classification library.
#
# Provides:
#   - SECRET_PATTERNS: ordered array of "regex|||type|||service|||rotate_url|||severity_hint"
#   - SECRETS_GREP_PATTERN: combined ERE for fast pre-filter
#   - redact_fingerprint <value>          → "AKIA****ABCD (20 chars)" — never the value
#   - classify_secret_match <value>       → "type|||service|||rotate_url|||severity_hint"
#   - scan_classify_to_inventory <file> <label>  → appends section to $SECRETS_INVENTORY,
#                                                   prints total count to stdout
#
# Privacy guarantee: only fingerprints (4 leading + 4 trailing chars + length) are persisted
# anywhere on disk or printed. Raw match values live only inside this process's memory.

# Inventory file used by scan_classify_to_inventory.
SECRETS_INVENTORY="${SECRETS_INVENTORY:-${AUDIT_DIR:-$HOME/.ai-agent-audit}/secrets-inventory.md}"

# Each entry: ERE-pattern|||human-readable type|||service / where it's used|||where to rotate|||severity hint
# Severity hints are advisory; the calling module decides actual severity for the finding.
# Order matters: more specific patterns must come before generic ones (e.g. sk-ant- before sk-).
SECRET_PATTERNS=(
  # --- AWS ---
  'AKIA[0-9A-Z]{16}|||AWS Access Key (long-lived IAM)|||AWS IAM|||AWS Console → IAM → Users → Security credentials → Deactivate/Delete access key|||HIGH'
  'ASIA[0-9A-Z]{16}|||AWS STS Session Token (short-lived)|||AWS STS|||Re-run aws sso login (auto-refreshed)|||LOW'

  # --- Google / GCP ---
  'AIza[0-9A-Za-z_\-]{35}|||Google API Key|||Google Cloud|||console.cloud.google.com → APIs & Services → Credentials → Delete/Regenerate key|||HIGH'
  'ya29\.[0-9A-Za-z_\-]{20,}|||Google OAuth Access Token|||Google OAuth|||myaccount.google.com → Security → Third-party access → Remove app|||HIGH'

  # --- AI providers (most specific first) ---
  'sk-ant-api03-[A-Za-z0-9_\-]{80,}|||Anthropic API Key (api03)|||console.anthropic.com|||console.anthropic.com → Settings → API Keys → Disable|||HIGH'
  'sk-ant-[A-Za-z0-9_\-]{40,}|||Anthropic API Key|||console.anthropic.com|||console.anthropic.com → Settings → API Keys → Disable|||HIGH'
  'sk-proj-[A-Za-z0-9_\-]{40,}|||OpenAI Project Key|||platform.openai.com|||platform.openai.com → API keys → Revoke|||HIGH'
  'sk-svcacct-[A-Za-z0-9_\-]{20,}|||OpenAI Service Account|||platform.openai.com|||platform.openai.com → Service Accounts → Delete|||HIGH'
  'sk-[A-Za-z0-9]{48}|||OpenAI Legacy Key (or generic sk-)|||platform.openai.com (likely)|||platform.openai.com → API keys → Revoke (verify provider first)|||MEDIUM'
  'hf_[A-Za-z0-9]{30,}|||HuggingFace Access Token|||huggingface.co|||huggingface.co → Settings → Access Tokens → Revoke|||HIGH'
  'r8_[A-Za-z0-9]{30,}|||Replicate API Token|||replicate.com|||replicate.com → Account → API tokens → Revoke|||HIGH'

  # --- Stripe ---
  'sk_live_[A-Za-z0-9]{20,}|||Stripe LIVE Secret Key|||dashboard.stripe.com (PRODUCTION)|||dashboard.stripe.com → Developers → API keys → Roll key (URGENT)|||CRITICAL'
  'rk_live_[A-Za-z0-9]{20,}|||Stripe LIVE Restricted Key|||dashboard.stripe.com (PRODUCTION)|||dashboard.stripe.com → Developers → API keys → Revoke|||CRITICAL'
  'sk_test_[A-Za-z0-9]{20,}|||Stripe TEST Secret Key|||dashboard.stripe.com (test mode)|||dashboard.stripe.com → Developers → API keys → Roll key|||MEDIUM'
  'rk_test_[A-Za-z0-9]{20,}|||Stripe TEST Restricted Key|||dashboard.stripe.com (test mode)|||dashboard.stripe.com → Developers → API keys → Revoke|||LOW'
  'pk_live_[A-Za-z0-9]{20,}|||Stripe LIVE Publishable Key|||dashboard.stripe.com|||No rotation needed (publishable is intentionally public)|||INFO'

  # --- DigitalOcean / Hetzner / linode ---
  'dop_v1_[A-Fa-f0-9]{64}|||DigitalOcean Personal Access Token|||cloud.digitalocean.com|||cloud.digitalocean.com → API → Tokens/Keys → Delete|||HIGH'

  # --- VCS hosts ---
  'ghp_[A-Za-z0-9]{30,}|||GitHub Classic PAT|||github.com|||github.com → Settings → Developer → PAT (classic) → Delete|||HIGH'
  'github_pat_[A-Za-z0-9_]{40,}|||GitHub Fine-grained PAT|||github.com|||github.com → Settings → Developer → Fine-grained tokens → Revoke|||HIGH'
  'gho_[A-Za-z0-9]{30,}|||GitHub OAuth Token|||github.com|||github.com → Settings → Applications → Authorized OAuth Apps → Revoke|||HIGH'
  'ghu_[A-Za-z0-9]{30,}|||GitHub User-to-server Token|||github.com|||Revoke OAuth App in GitHub Settings|||HIGH'
  'ghs_[A-Za-z0-9]{30,}|||GitHub App Server-to-server Token|||github.com|||GitHub App settings → Regenerate token|||HIGH'
  'ghr_[A-Za-z0-9]{30,}|||GitHub Refresh Token|||github.com|||Revoke OAuth App in GitHub Settings|||HIGH'
  'glpat-[A-Za-z0-9_\-]{20,}|||GitLab Personal Access Token|||gitlab.com|||gitlab.com → User → Preferences → Access Tokens → Revoke|||HIGH'

  # --- Package registries ---
  'npm_[A-Za-z0-9]{36}|||npm Auth Token|||npmjs.com|||npmjs.com → Account → Access Tokens → Revoke|||HIGH'
  'pypi-AgEIc[A-Za-z0-9_\-]{20,}|||PyPI API Token|||pypi.org|||pypi.org → Account → API tokens → Revoke|||HIGH'

  # --- Communication platforms ---
  'xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}|||Slack Bot Token|||api.slack.com|||api.slack.com → App → OAuth & Permissions → Reinstall|||HIGH'
  'xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}|||Slack User Token|||api.slack.com|||Revoke via app config|||HIGH'
  'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|||Slack Incoming Webhook URL|||api.slack.com|||App config → Incoming Webhooks → Delete|||HIGH'
  'discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+|||Discord Webhook URL|||discord.com|||Server Settings → Integrations → Webhooks → Delete|||HIGH'
  '[0-9]{9,10}:AA[A-Za-z0-9_\-]{33}|||Telegram Bot Token|||t.me/BotFather|||Open chat with @BotFather → /revoke|||HIGH'

  # --- Database connection strings ---
  'postgres(ql)?://[^:@[:space:]]+:[^@[:space:]]+@[A-Za-z0-9._\-]+|||Postgres URL with password|||DB infrastructure|||Rotate DB password via DB management panel / mgmt CLI|||HIGH'
  'mysql://[^:@[:space:]]+:[^@[:space:]]+@[A-Za-z0-9._\-]+|||MySQL URL with password|||DB infrastructure|||Rotate DB password via mgmt panel|||HIGH'
  'mongodb(\+srv)?://[^:@[:space:]]+:[^@[:space:]]+@[A-Za-z0-9._\-]+|||MongoDB URL with password|||DB infrastructure|||Atlas / mgmt panel → Reset DB user password|||HIGH'
  'redis://[^:@[:space:]]+:[^@[:space:]]+@[A-Za-z0-9._\-]+|||Redis URL with password|||DB infrastructure|||Reset Redis AUTH (CONFIG SET requirepass) and update consumers|||HIGH'
  'amqps?://[^:@[:space:]]+:[^@[:space:]]+@[A-Za-z0-9._\-]+|||AMQP URL with password|||Message broker|||RabbitMQ admin → Users → Set password|||HIGH'

  # --- Generic high-value patterns ---
  '-----BEGIN[ A-Z]+PRIVATE KEY-----|||PEM Private Key (raw)|||varies (SSH/TLS/JWT signing)|||Generate new keypair, distribute new pubkey, retire old|||HIGH'
  'eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}|||JWT (signed token)|||varies|||Invalidate session / rotate signing key|||MEDIUM'
)

# Combined ERE pattern (used as fast filter; modules can grep -qE "$SECRETS_GREP_PATTERN")
build_secrets_grep_pattern() {
  local out="" entry pat
  for entry in "${SECRET_PATTERNS[@]}"; do
    pat="${entry%%|||*}"
    if [[ -z "$out" ]]; then
      out="$pat"
    else
      out="$out|$pat"
    fi
  done
  printf '%s' "$out"
}
SECRETS_GREP_PATTERN="$(build_secrets_grep_pattern)"
export SECRETS_GREP_PATTERN

# Redact a secret to a fingerprint: "AKIA****ABCD (20 chars)".
# For very short matches, returns just "**** (N chars)" — never leaks middle bytes.
redact_fingerprint() {
  local s="$1"
  local n=${#s}
  if (( n <= 8 )); then
    printf '**** (%d chars)' "$n"
  elif (( n <= 12 )); then
    printf '%s****%s (%d chars)' "${s:0:2}" "${s: -2}" "$n"
  else
    printf '%s****%s (%d chars)' "${s:0:4}" "${s: -4}" "$n"
  fi
}

# Classify a single matched value. Output: "type|||service|||rotate|||sev_hint" or "Unknown|||...|||MEDIUM" if no pattern matched.
classify_secret_match() {
  local m="$1" entry pat type_label service rotate sev rest
  for entry in "${SECRET_PATTERNS[@]}"; do
    pat="${entry%%|||*}"; rest="${entry#*|||}"
    type_label="${rest%%|||*}"; rest="${rest#*|||}"
    service="${rest%%|||*}"; rest="${rest#*|||}"
    rotate="${rest%%|||*}"; rest="${rest#*|||}"
    sev="${rest%%|||*}"
    if printf '%s' "$m" | grep -qE "^$pat$"; then
      printf '%s|||%s|||%s|||%s' "$type_label" "$service" "$rotate" "$sev"
      return 0
    fi
  done
  printf 'Unknown high-entropy string|||unknown|||Manual review (compare prefix to vendor docs)|||MEDIUM'
}

# Build header for the inventory file (idempotent — only writes once per audit run).
ensure_secrets_inventory_header() {
  if [[ ! -f "$SECRETS_INVENTORY" ]] || [[ ! -s "$SECRETS_INVENTORY" ]]; then
    {
      echo "# Secrets Inventory"
      echo
      echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo
      echo "Detected secrets across history files, AI tool sessions, and configs."
      echo "**No raw values are stored anywhere** — only redacted fingerprints (first 4 + last 4 chars + length)."
      echo "Use the fingerprint to identify which key it is in your provider's UI when rotating."
      echo
      echo "**Severity hints** are per-pattern advisories; the audit-report.md owns the final finding severity."
      echo
    } > "$SECRETS_INVENTORY"
  fi
}

# Scan a file, classify each unique match, append a section to the inventory file.
# Echoes the total number of distinct secret matches found (0 if none).
# Args: <file_path> <human_label>
scan_classify_to_inventory() {
  local file="$1" label="$2"
  [[ -r "$file" ]] || { printf '0'; return; }

  ensure_secrets_inventory_header

  # Collect unique matches per pattern. Use a tmp file to keep them out of any global
  # variable that might accidentally be exported.
  local tmp; tmp=$(mktemp)
  local total=0

  local entry pat type_label service rotate sev rest matches match fp row

  for entry in "${SECRET_PATTERNS[@]}"; do
    pat="${entry%%|||*}"; rest="${entry#*|||}"
    type_label="${rest%%|||*}"; rest="${rest#*|||}"
    service="${rest%%|||*}"; rest="${rest#*|||}"
    rotate="${rest%%|||*}"; rest="${rest#*|||}"
    sev="${rest%%|||*}"

    matches=$(grep -oE "$pat" "$file" 2>/dev/null | sort -u)
    [[ -z "$matches" ]] && continue

    while IFS= read -r match; do
      [[ -z "$match" ]] && continue
      fp=$(redact_fingerprint "$match")
      # Escape pipes in fields (rare but possible in DB URLs).
      local t_esc="${type_label//|/\\|}"
      local s_esc="${service//|/\\|}"
      local r_esc="${rotate//|/\\|}"
      printf '| %s | %s | %s | %s | `%s` |\n' "$t_esc" "$s_esc" "$r_esc" "$sev" "$fp" >> "$tmp"
      total=$((total+1))
    done <<<"$matches"
  done

  if [[ "$total" -eq 0 ]]; then
    rm -f "$tmp"
    printf '0'
    return
  fi

  {
    echo
    echo "## Source: $label"
    echo
    echo "Path: \`$file\`"
    echo
    echo "| Type | Service | Where to rotate | Severity hint | Sample (redacted) |"
    echo "|------|---------|-----------------|--------------:|-------------------|"
    cat "$tmp"
  } >> "$SECRETS_INVENTORY"

  rm -f "$tmp"
  printf '%s' "$total"
}

# Same as scan_classify_to_inventory but reads from stdin (for piping sqlite3 output etc.).
# Args: <human_label>
scan_classify_stdin_to_inventory() {
  local label="$1"
  local tmp_in; tmp_in=$(mktemp)
  cat > "$tmp_in"
  scan_classify_to_inventory "$tmp_in" "$label"
  rm -f "$tmp_in"
}

# Aggregate scan across multiple files (e.g. Claude Code sessions).
# Renders a single inventory section listing unique fingerprints found across all of them.
# Args: <label> <subtitle_or_empty> <file...>
scan_classify_files_aggregated() {
  local label="$1" subtitle="$2"; shift 2
  local files=("$@")
  local merged; merged=$(mktemp)

  local f
  for f in "${files[@]}"; do
    [[ -r "$f" ]] || continue
    grep -hoE "$SECRETS_GREP_PATTERN" "$f" 2>/dev/null >> "$merged" || true
  done

  if [[ ! -s "$merged" ]]; then
    rm -f "$merged"
    printf '0'
    return
  fi

  ensure_secrets_inventory_header

  local total=0
  local tmp_table; tmp_table=$(mktemp)

  local entry pat type_label service rotate sev rest matches match fp
  for entry in "${SECRET_PATTERNS[@]}"; do
    pat="${entry%%|||*}"; rest="${entry#*|||}"
    type_label="${rest%%|||*}"; rest="${rest#*|||}"
    service="${rest%%|||*}"; rest="${rest#*|||}"
    rotate="${rest%%|||*}"; rest="${rest#*|||}"
    sev="${rest%%|||*}"

    matches=$(grep -oE "^$pat$" "$merged" 2>/dev/null | sort -u)
    [[ -z "$matches" ]] && continue

    while IFS= read -r match; do
      [[ -z "$match" ]] && continue
      fp=$(redact_fingerprint "$match")
      printf '| %s | %s | %s | %s | `%s` |\n' "$type_label" "$service" "$rotate" "$sev" "$fp" >> "$tmp_table"
      total=$((total+1))
    done <<<"$matches"
  done

  rm -f "$merged"

  if [[ "$total" -eq 0 ]]; then
    rm -f "$tmp_table"
    printf '0'
    return
  fi

  {
    echo
    echo "## Source: $label"
    echo
    [[ -n "$subtitle" ]] && echo "$subtitle" && echo
    echo "| Type | Service | Where to rotate | Severity hint | Sample (redacted) |"
    echo "|------|---------|-----------------|--------------:|-------------------|"
    cat "$tmp_table"
  } >> "$SECRETS_INVENTORY"

  rm -f "$tmp_table"
  printf '%s' "$total"
}

export -f redact_fingerprint classify_secret_match \
          ensure_secrets_inventory_header \
          scan_classify_to_inventory scan_classify_stdin_to_inventory \
          scan_classify_files_aggregated
