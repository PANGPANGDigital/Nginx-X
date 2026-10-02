#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/../nx.sh"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
# shellcheck disable=SC2034
SUDO=""
SSL_DIR="$root/ssl"
CONF_DIR="$root/conf"
mkdir -p "$SSL_DIR" "$CONF_DIR"
# Override the acme home only in this isolated test process.
export HOME="$root/home"
mkdir -p "$HOME/.acme.sh"
export ACME_LOG="$root/acme.log"
cat > "$HOME/.acme.sh/acme.sh" <<'MOCK'
#!/bin/bash
printf '%s\n' "$@" >> "$ACME_LOG"
[[ "${FAIL_ISSUE:-0}:$1" != 1:--issue ]] || exit 8
[[ "${FAIL_DEPLOY:-0}:$1" != 1:--install-cert ]] || exit 9
while (($#)); do
 case "$1" in --key-file|--fullchain-file) printf certificate > "$2"; shift ;; esac
 shift
done
MOCK
chmod +x "$HOME/.acme.sh/acme.sh"
# shellcheck disable=SC2034
load_email() { ACME_EMAIL=test@example.com; }
has_dns_config() { return 0; }
get_dns_issue_args() { echo '--dns dns_cf'; }
# shellcheck disable=SC2317
export_dns_env() { :; }
export FAIL_ISSUE=1
if _issue_cert_dns example.com; then exit 1; fi
if grep -q -- --install-cert "$ACME_LOG"; then exit 1; fi
export FAIL_ISSUE=0 FAIL_DEPLOY=1
if _issue_cert_dns example.com; then exit 1; fi
[[ ! -e "$root/cron" ]]
export FAIL_DEPLOY=0
crontab() { if [[ "$1" == -l ]]; then cat "$root/cron" 2>/dev/null; else cat > "$root/cron"; fi; }
printf '7 4 * * * unrelated\n0 3 1 */2 * %s/.acme.sh/acme.sh --cron --home %s/.acme.sh >/dev/null\n' "$HOME" "$HOME" > "$root/cron"
_issue_cert_dns example.com
grep -Fq -- --reloadcmd "$ACME_LOG"
[[ -x "$HOME/.acme.sh/nginxx-reload" ]]
sh -n "$HOME/.acme.sh/nginxx-reload"
# Exercise persisted hook in a fresh process with an isolated PATH. No host service.
mkdir "$root/bin"
cat > "$root/bin/nginx" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$HOOK_LOG"
[ "${HOOK_FAIL:-0}:$1" != 1:-t ]
MOCK
cat > "$root/bin/systemctl" <<'MOCK'
#!/bin/sh
printf 'reload\n' >> "$HOOK_LOG"
exit "${RELOAD_FAIL:-0}"
MOCK
chmod +x "$root/bin/"*
sed "s|^PATH=.*|PATH=$root/bin:/usr/bin:/bin|" "$HOME/.acme.sh/nginxx-reload" > "$root/hook"
export HOOK_LOG="$root/hook.log" HOOK_FAIL=1
if sh "$root/hook"; then exit 1; fi
[[ "$(wc -l < "$HOOK_LOG")" == 1 ]]
export HOOK_FAIL=0 RELOAD_FAIL=1
if sh "$root/hook"; then exit 1; fi
export RELOAD_FAIL=0
sh "$root/hook"
grep -q '^nginx -t || exit' "$HOME/.acme.sh/nginxx-reload"
grep -q '^0 3 \* \* \* ' "$root/cron"
grep -q '^7 4 \* \* \* unrelated$' "$root/cron"
ensure_acme_cron
[[ "$(grep -c -- --cron "$root/cron")" == 1 ]]
apply_conf_with_rollback() { cp "$1" "$2"; }
reload_nginx_safe() { :; }
precheck_http01() { :; }
cat > "$CONF_DIR/unrelated.conf" <<'CONF'
server { listen 127.0.0.1:80; server_name notexample.com; location / { return 200 okay; } }
CONF
_issue_cert_http example.com
[[ -f "$CONF_DIR/acme-challenge-example.com.conf" ]]
# Exact names and compact address listeners: do not create duplicate helpers.
rm "$CONF_DIR/acme-challenge-example.com.conf"
cat > "$CONF_DIR/site.conf" <<'CONF'
server { listen 127.0.0.1:80; server_name example.com; return 301 https://$host$request_uri; }
CONF
ensure_acme_location_for_domain_conf example.com
grep -Fq 'location / { return 301' "$CONF_DIR/site.conf"
grep -Fq 'location ^~ /.well-known/acme-challenge/' "$CONF_DIR/site.conf"
[[ -z "$(ensure_http_challenge_server example.com)" ]]
ensure_websocket_map() { :; }
if build_external_proxy_conf example.com 8080 http://127.0.0.1 normal "$root/bad" 0 '' '' '"; add_header Evil yes; #'; then exit 1; fi
[[ ! -e "$root/bad" ]]
# Loading long provider names must export the canonical plugin credentials.
unset -f export_dns_env
# shellcheck disable=SC1091
source "$(dirname "$0")/../lib/certificates.sh"
ensure_state_dir() { :; }
DNS_CONF="$root/dns.conf"
printf 'DNS_PROVIDER=cloudflare\nDNS_KEY1=test-token\n' > "$DNS_CONF"
export_dns_env
# shellcheck disable=SC2154
[[ "$DNS_PROVIDER" == cf && "$CF_Token" == test-token ]]
# Legacy monthly periodic job migrates alongside the daily crontab.
NX_PERIODIC_DIR="$root/periodic"
mkdir -p "$NX_PERIODIC_DIR/monthly"
printf '#!/bin/sh\n%s/.acme.sh/acme.sh --cron --home %s/.acme.sh >/dev/null\n' "$HOME" "$HOME" > "$NX_PERIODIC_DIR/monthly/acme-renew"
ensure_acme_cron
[[ ! -f "$NX_PERIODIC_DIR/monthly/acme-renew" ]]
echo 'certificate audit regressions passed' 
