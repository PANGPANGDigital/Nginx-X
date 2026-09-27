#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

TMPDIR_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

MOCK_BIN="$TMPDIR_ROOT/bin"
mkdir -p "$MOCK_BIN"
cat > "$MOCK_BIN/nginx" <<'EOF'
#!/usr/bin/env bash
if [[ "${NGINX_MOCK_FAIL:-0}" == "1" ]]; then
  exit 1
fi
exit 0
EOF
cat > "$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${SYSTEMCTL_MOCK_FAIL:-0}" == "1" ]]; then
  exit 1
fi
case "$1" in
  is-active) exit 1 ;;
  start|reload) exit 0 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$MOCK_BIN/nginx" "$MOCK_BIN/systemctl"
export PATH="$MOCK_BIN:$PATH"

# shellcheck disable=SC1091
source nx.sh

# Make the test deterministic: don't depend on the host kernel IPv6 state.
ipv6_available() { return 0; }

# shellcheck disable=SC2034
SUDO=""
CONF_DIR="$TMPDIR_ROOT/conf.d"
SSL_DIR="$TMPDIR_ROOT/ssl"
STATE_DIR="$TMPDIR_ROOT/state"
DOMAIN_ONLY_STATE="$STATE_DIR/domain-only.conf"
DOMAIN_ONLY_CONF="${CONF_DIR}/00-nx-domain-only.conf"
mkdir -p "$CONF_DIR" "$SSL_DIR" "$STATE_DIR"

mkdir -p "$SSL_DIR/site-https.example.com" "$SSL_DIR/site-mixed.example.com"
for cn in site-https.example.com site-mixed.example.com; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=${cn}" \
    -keyout "$SSL_DIR/${cn}/privkey.pem" \
    -out "$SSL_DIR/${cn}/fullchain.pem" >/dev/null 2>&1
done

write_site_http() {
  cat > "$CONF_DIR/site-http.example.com-80.conf" <<'EOF'
# managed_by=Nginx-X
# domain=site-http.example.com
# listen_port=80
# backend_port=3000
server {
    listen 80;
    listen [::]:80;
    server_name site-http.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
EOF
}

write_site_https() {
  cat > "$CONF_DIR/site-https.example.com-443.conf" <<EOF
# managed_by=Nginx-X
# domain=site-https.example.com
# listen_port=443
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name site-https.example.com;
    ssl_certificate     ${SSL_DIR}/site-https.example.com/fullchain.pem;
    ssl_certificate_key ${SSL_DIR}/site-https.example.com/privkey.pem;
}
EOF
}

write_site_mixed() {
  cat > "$CONF_DIR/site-mixed.example.com-18843.conf" <<EOF
# managed_by=Nginx-X
# domain=site-mixed.example.com
# listen_port=18843
server {
    listen 18843;
    listen [::]:18843;
    server_name site-mixed.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
server {
    listen 18843 ssl;
    listen [::]:18843 ssl;
    server_name site-mixed.example.com;
    ssl_certificate     ${SSL_DIR}/site-mixed.example.com/fullchain.pem;
    ssl_certificate_key ${SSL_DIR}/site-mixed.example.com/privkey.pem;
}
EOF
}

write_site_http
write_site_https
write_site_mixed

# A managed conf bound to a specific address must not join the catch-all.
cat > "$CONF_DIR/status-app.example.com-18088.conf" <<'EOF'
# managed_by=Nginx-X
# domain=status-app.example.com
# listen_port=18088
server {
    listen 127.0.0.1:18088;
    server_name status-app.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
EOF

# 1) collect: wildcard ports are classified, address-bound listens are ignored
collected="$(domain_only_collect_ports)"
grep -qx 'plain 80' <<<"$collected"
grep -qx 'ssl 443' <<<"$collected"
grep -qx 'plain 18843' <<<"$collected"
grep -qx 'ssl 18843' <<<"$collected"
if grep -q '18088' <<<"$collected"; then
  echo "address-bound listen must not join the catch-all" >&2
  exit 1
fi

# 2) build (nginx >= 1.19.4): ssl-only ports reject the handshake, mixed ports
#    fall back to a self-signed placeholder certificate on the same socket
nginx_local_version() { echo "1.25.0"; }
catchall="$TMPDIR_ROOT/catchall-modern.conf"
build_domain_only_conf "$catchall" >/dev/null 2>&1
grep -q 'listen 80 default_server;' "$catchall"
grep -q 'listen \[::\]:80 default_server;' "$catchall"
grep -Fq 'return 444;' "$catchall"
grep -q 'listen 443 ssl default_server;' "$catchall"
grep -q 'listen \[::\]:443 ssl default_server;' "$catchall"
grep -q 'ssl_reject_handshake on;' "$catchall"
grep -q 'listen 18843 ssl default_server;' "$catchall"
grep -q 'listen \[::\]:18843 ssl default_server;' "$catchall"
grep -q "ssl_certificate     ${SSL_DIR}/nx-domain-only/fullchain.pem;" "$catchall"
grep -q "ssl_certificate_key ${SSL_DIR}/nx-domain-only/privkey.pem;" "$catchall"
[[ -f "$SSL_DIR/nx-domain-only/fullchain.pem" ]]
[[ "$(stat -c '%a' "$SSL_DIR/nx-domain-only/privkey.pem")" == "600" ]]

# ensure_ssl_directives_present accepts the reject-based ssl block without a cert
ensure_ssl_directives_present "$catchall" >/dev/null

# 3) build (nginx < 1.19.4): ssl-only ports fall back to the placeholder cert
nginx_local_version() { echo "1.18.0"; }
catchall_old="$TMPDIR_ROOT/catchall-legacy.conf"
build_domain_only_conf "$catchall_old" >/dev/null 2>&1
grep -q "ssl_certificate     ${SSL_DIR}/nx-domain-only/fullchain.pem;" "$catchall_old"
if grep -q 'ssl_reject_handshake' "$catchall_old"; then
  echo "legacy nginx build must not use ssl_reject_handshake" >&2
  exit 1
fi
ensure_ssl_directives_present "$catchall_old" >/dev/null
nginx_local_version() { echo "1.25.0"; }

# 4) ports with an existing default_server are skipped with a warning
cat > "$CONF_DIR/user-custom.conf" <<'EOF'
server {
    listen 18099 default_server;
    server_name _;
    return 444;
}
EOF
cat > "$CONF_DIR/site-app.example.com-18099.conf" <<'EOF'
# managed_by=Nginx-X
# domain=site-app.example.com
# listen_port=18099
server {
    listen 18099;
    server_name site-app.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
EOF
catchall_skip="$TMPDIR_ROOT/catchall-skip.conf"
build_out="$(build_domain_only_conf "$catchall_skip" 2>&1)"
grep -q 'default_server 配置' <<<"$build_out"
if grep -q '18099' "$catchall_skip"; then
  echo "port with existing default_server should be skipped" >&2
  exit 1
fi
grep -q 'listen 80 default_server;' "$catchall_skip"
rm -f "$CONF_DIR/user-custom.conf" "$CONF_DIR/site-app.example.com-18099.conf"

# 5) enable writes the catch-all and records state
domain_only_enable >/dev/null
[[ -f "$DOMAIN_ONLY_CONF" ]]
[[ "$(stat -c '%a' "$DOMAIN_ONLY_STATE")" == "600" ]]
[[ "$(cat "$DOMAIN_ONLY_STATE")" == "DOMAIN_ONLY=1" ]]
grep -q 'listen 80 default_server;' "$DOMAIN_ONLY_CONF"
grep -q 'listen 443 ssl default_server;' "$DOMAIN_ONLY_CONF"

# 6) enable must roll back completely when nginx -t fails
rm -f "$DOMAIN_ONLY_CONF" "$DOMAIN_ONLY_STATE"
if NGINX_MOCK_FAIL=1 domain_only_enable >/dev/null 2>&1; then
  echo "enable should fail when nginx -t fails" >&2
  exit 1
fi
[[ ! -f "$DOMAIN_ONLY_CONF" ]]
[[ ! -f "$DOMAIN_ONLY_STATE" ]]

# 7) disable removes the catch-all and resets state
domain_only_enable >/dev/null
domain_only_disable >/dev/null
[[ ! -f "$DOMAIN_ONLY_CONF" ]]
[[ "$(cat "$DOMAIN_ONLY_STATE")" == "DOMAIN_ONLY=0" ]]

# 8) disable must restore the catch-all when nginx -t fails
domain_only_enable >/dev/null
catchall_before="$(cat "$DOMAIN_ONLY_CONF")"
if NGINX_MOCK_FAIL=1 domain_only_disable >/dev/null 2>&1; then
  echo "disable should fail when nginx -t fails" >&2
  exit 1
fi
[[ "$(cat "$DOMAIN_ONLY_CONF")" == "$catchall_before" ]]
[[ "$(cat "$DOMAIN_ONLY_STATE")" == "DOMAIN_ONLY=1" ]]

# 9) disabling a site syncs the catch-all ports
disable_conf "site-https.example.com-443.conf" >/dev/null
if grep -q 'listen 443 ssl' "$DOMAIN_ONLY_CONF"; then
  echo "disabled site port should be removed from the catch-all" >&2
  exit 1
fi
grep -q 'listen 80 default_server;' "$DOMAIN_ONLY_CONF"
grep -q 'listen 18843 ssl default_server;' "$DOMAIN_ONLY_CONF"

# 10) enabling a site syncs the catch-all ports
enable_conf "site-https.example.com-443.conf.bak" >/dev/null
grep -q 'listen 443 ssl default_server;' "$DOMAIN_ONLY_CONF"

# 11) deleting a site syncs the catch-all ports
printf 'y\n' | delete_conf "site-http.example.com-80.conf" >/dev/null
if grep -q 'listen 80 default_server;' "$DOMAIN_ONLY_CONF"; then
  echo "deleted site port should be removed from the catch-all" >&2
  exit 1
fi
grep -q 'listen 443 ssl default_server;' "$DOMAIN_ONLY_CONF"

# 12) applying a new site config syncs the catch-all (add-flow path)
build_proxy_conf "site-http2.example.com" "80" "3001" "$TMPDIR_ROOT/new-site.conf"
apply_conf_with_rollback "$TMPDIR_ROOT/new-site.conf" "$CONF_DIR/site-http2.example.com-80.conf" >/dev/null
grep -q 'listen 80 default_server;' "$DOMAIN_ONLY_CONF"

# 13) the catch-all conf must stay out of the managed list and import scan
managed_list="$(list_managed_conf_files 1)"
if grep -q '00-nx-domain-only.conf' <<<"$managed_list"; then
  echo "catch-all conf leaked into managed config list" >&2
  exit 1
fi
cat > "$CONF_DIR/00-nx-domain-only.conf.decoy" <<'EOF'
server {
    listen 19001;
    server_name decoy.example.com;
}
EOF
scan_out="$(_scan_unmanaged_confs 2>/dev/null || true)"
grep -q '00-nx-domain-only.conf.decoy' <<<"$scan_out"
scan_names="$(sed -E 's#.*/##' <<<"$scan_out")"
if grep -q '^00-nx-domain-only.conf$' <<<"$scan_names"; then
  echo "catch-all conf leaked into import scan" >&2
  exit 1
fi
rm -f "$CONF_DIR/00-nx-domain-only.conf.decoy"

# 14) real nginx validation of the generated catch-all (runs in CI)
REAL_NGINX=""
IFS=':' read -r -a path_dirs <<< "$PATH"
for d in "${path_dirs[@]}"; do
  if [[ -n "$d" && "$d" != "$MOCK_BIN" && -x "$d/nginx" ]]; then
    REAL_NGINX="$d/nginx"
    break
  fi
done

if [[ -n "$REAL_NGINX" ]]; then
  rm -f "${CONF_DIR}"/*.conf "${CONF_DIR}"/*.conf.* 2>/dev/null || true
  write_site_http
  write_site_https
  write_site_mixed

  real_ver="$("$REAL_NGINX" -v 2>&1 | sed -E 's#^nginx version: nginx/##')"
  nginx_local_version() { echo "$real_ver"; }
  build_domain_only_conf "$DOMAIN_ONLY_CONF" >/dev/null 2>&1
  grep -q 'listen 80 default_server;' "$DOMAIN_ONLY_CONF"
  grep -q 'listen 443 ssl default_server;' "$DOMAIN_ONLY_CONF"
  grep -q 'listen 18843 ssl default_server;' "$DOMAIN_ONLY_CONF"
  grep -q "ssl_certificate     ${SSL_DIR}/nx-domain-only/fullchain.pem;" "$DOMAIN_ONLY_CONF"

  NGINX_MAIN_CONF="$TMPDIR_ROOT/nginx-main.conf"
  mkdir -p "$TMPDIR_ROOT/body" "$TMPDIR_ROOT/proxy" "$TMPDIR_ROOT/fastcgi" "$TMPDIR_ROOT/uwsgi" "$TMPDIR_ROOT/scgi"
  cat > "$NGINX_MAIN_CONF" <<EOF
pid ${TMPDIR_ROOT}/nginx.pid;
error_log stderr;
events {}
http {
    access_log off;
    client_body_temp_path ${TMPDIR_ROOT}/body;
    proxy_temp_path ${TMPDIR_ROOT}/proxy;
    fastcgi_temp_path ${TMPDIR_ROOT}/fastcgi;
    uwsgi_temp_path ${TMPDIR_ROOT}/uwsgi;
    scgi_temp_path ${TMPDIR_ROOT}/scgi;
    include ${CONF_DIR}/*.conf;
}
EOF

  if [[ ${EUID:-0} -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    sudo "$REAL_NGINX" -t -p "$TMPDIR_ROOT/" -c "$NGINX_MAIN_CONF"
  else
    "$REAL_NGINX" -t -p "$TMPDIR_ROOT/" -c "$NGINX_MAIN_CONF"
  fi
else
  echo "skip: real nginx not available for catch-all validation" >&2
fi

echo "ok"
