#!/usr/bin/env bash
# Nginx-X certificate issuance and renewal helpers.
load_dns_conf() {
  ensure_state_dir
  if [[ -f "$DNS_CONF" ]]; then
    # shellcheck disable=SC1090
    . "$DNS_CONF"
  fi
}

save_dns_conf() {
  local provider="$1"
  local key1="$2"
  local key2="$3"
  ensure_state_dir
  # 密钥属于敏感信息，先设置只读权限再写入，避免明文密钥被同机其他用户读到。
  (
    umask 077
    {
      printf 'DNS_PROVIDER=%q\n' "$provider"
      printf 'DNS_KEY1=%q\n' "$key1"
      printf 'DNS_KEY2=%q\n' "$key2"
    } > "$DNS_CONF"
  )
  chmod 600 "$DNS_CONF" 2>/dev/null || true
  info "DNS API 配置已保存到：${DNS_CONF}（权限 600）。"
  warn "提醒：DNS API 密钥以明文存储于该文件，请自行保护该主机的账户权限。"
}

has_dns_config() {
  load_dns_conf
  [[ -n "${DNS_PROVIDER:-}" && -n "${DNS_KEY1:-}" ]]
}

get_dns_issue_args() {
  load_dns_conf
  case "${DNS_PROVIDER:-}" in
    cf|cloudflare)
      echo "--dns dns_cf"
      ;;
    dp|dnspod)
      echo "--dns dns_dp"
      ;;
    ali|alidns)
      echo "--dns dns_ali"
      ;;
    he|he.net)
      echo "--dns dns_he"
      ;;
    gd|godaddy)
      echo "--dns dns_gd"
      ;;
    hw|huaweicloud)
      echo "--dns dns_huaweicloud"
      ;;
    aws|route53)
      echo "--dns dns_aws"
      ;;
    google|gcp)
      echo "--dns dns_gcloud"
      ;;
    *)
      echo ""
      ;;
  esac
}

setup_dns_api() {
  local choice provider key1 key2
  echo "选择 DNS 服务商："
  echo "1)  Cloudflare      (CF_Token)"
  echo "2)  DNSPod          (DP_Id + DP_Key)"
  echo "3)  阿里云 DNS      (Ali_Key + Ali_Secret)"
  echo "4)  HE.net          (HE_Username + HE_Password)"
  echo "5)  GoDaddy         (GD_Key + GD_Secret)"
  echo "6)  华为云          (HUAWEICLOUD_Username + HUAWEICLOUD_Password)"
  echo "7)  AWS Route53     (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)"
  echo "8)  Google Cloud    (GCE_Project + GCE_ServiceAccountEmail)"
  read -rp "请选择 [1-8]: " choice

  case "$choice" in
    1) provider="cf"; read -rp "Cloudflare API Token: " key1 ;;
    2) provider="dp"; read -rp "DNSPod ID: " key1; read -rp "DNSPod Key: " key2 ;;
    3) provider="ali"; read -rp "Aliyun AccessKey ID: " key1; read -rp "Aliyun AccessKey Secret: " key2 ;;
    4) provider="he"; read -rp "HE.net Username: " key1; read -rp "HE.net Password: " key2 ;;
    5) provider="gd"; read -rp "GoDaddy API Key: " key1; read -rp "GoDaddy API Secret: " key2 ;;
    6) provider="hw"; read -rp "华为云 Username: " key1; read -rp "华为云 Password: " key2 ;;
    7) provider="aws"; read -rp "AWS Access Key ID: " key1; read -rp "AWS Secret Access Key: " key2 ;;
    8) provider="google"; read -rp "GCE Project: " key1; read -rp "Service Account Email: " key2 ;;
    *) error "无效选择。"; return 1 ;;
  esac
  [[ -z "$key1" ]] && { error "API Key 不能为空。"; return 1; }

  save_dns_conf "$provider" "$key1" "${key2:-}"

  # Export env vars for acme.sh
  case "$provider" in
    cf) export CF_Token="$key1" ;;
    dp) export DP_Id="$key1"; export DP_Key="$key2" ;;
    ali) export Ali_Key="$key1"; export Ali_Secret="$key2" ;;
    he) export HE_Username="$key1"; export HE_Password="$key2" ;;
    gd) export GD_Key="$key1"; export GD_Secret="$key2" ;;
    hw) export HUAWEICLOUD_Username="$key1"; export HUAWEICLOUD_Password="$key2" ;;
    aws) export AWS_ACCESS_KEY_ID="$key1"; export AWS_SECRET_ACCESS_KEY="$key2" ;;
    google) export GCE_Project="$key1"; export GCE_ServiceAccountEmail="$key2" ;;
  esac

  info "DNS API 配置完成（${provider}）。"
  if confirm "是否现在测试申请证书？"; then
    local test_domain
    read -rp "请输入测试域名: " test_domain
    if valid_domain "$test_domain"; then
      _issue_cert_dns "$test_domain"
    fi
  fi
}

export_dns_env() {
  load_dns_conf
  # DNS_KEY1/DNS_KEY2 are sourced from $DNS_CONF by load_dns_conf; shellcheck can't see the assignment.
  # shellcheck disable=SC2153
  case "${DNS_PROVIDER:-}" in
    cf) export CF_Token="${DNS_KEY1}" ;;
    dp) export DP_Id="${DNS_KEY1}"; export DP_Key="${DNS_KEY2}" ;;
    ali) export Ali_Key="${DNS_KEY1}"; export Ali_Secret="${DNS_KEY2}" ;;
    he) export HE_Username="${DNS_KEY1}"; export HE_Password="${DNS_KEY2}" ;;
    gd) export GD_Key="${DNS_KEY1}"; export GD_Secret="${DNS_KEY2}" ;;
    hw) export HUAWEICLOUD_Username="${DNS_KEY1}"; export HUAWEICLOUD_Password="${DNS_KEY2}" ;;
    aws) export AWS_ACCESS_KEY_ID="${DNS_KEY1}"; export AWS_SECRET_ACCESS_KEY="${DNS_KEY2}" ;;
    google) export GCE_Project="${DNS_KEY1}"; export GCE_ServiceAccountEmail="${DNS_KEY2}" ;;
  esac
}

detect_cert_mode() {
  # 返回 http 或 dns（自动检测最适合的验证方式）
  # NAT 机没有 80 端口时自动返回 dns
  if ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | grep -qE '(^|:)80$'; then
    echo "http"
  elif has_dns_config; then
    echo "dns"
  else
    echo "http"
  fi
}

select_cert_mode_interactive() {
  # 交互式选择证书验证方式，返回 "http" 或 "dns"
  # 注意：此函数被 $(...) 调用，所有用户提示必须输出到 stderr 才能显示
  local choice=""
  >&2 echo "Select cert verification method:"
  >&2 echo "1) HTTP-01  (requires port 80 reachable)"
  >&2 echo "2) DNS-01   (requires DNS API Token, for NAT/no-port80)"

  local default_choice="1"
  if ! ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | grep -qE '(^|:)80$'; then
    >&2 warn "Port 80 not detected, DNS-01 suggested."
    default_choice="2"
  fi

  read -rp "Choose [1-2] (default ${default_choice}): " choice
  [[ -z "$choice" ]] && choice="$default_choice"

  case "$choice" in
    2)
      if ! has_dns_config; then
        >&2 warn "DNS API Token not configured, please set up first."
        if ! setup_dns_api >&2; then
          >&2 error "DNS API setup failed, fallback to HTTP-01."
          echo "http"
          return 0
        fi
      fi
      echo "dns"
      ;;
    *)
      echo "http"
      ;;
  esac
}

_issue_cert_dns() {
  local domain="$1"
  local dns_args issue_output retry_after

  load_email
  if [[ -z "${ACME_EMAIL:-}" ]]; then
    error "未设置邮箱，无法申请证书。"
    return 1
  fi

  if ! has_dns_config; then
    error "未配置 DNS API。请先在证书管理里执行 [3) 配置 DNS API]。"
    return 1
  fi

  dns_args="$(get_dns_issue_args)"
  if [[ -z "$dns_args" ]]; then
    error "不支持的 DNS 服务商配置，请重新设置。"
    return 1
  fi

  ensure_acme_installed || return 1

  note "开始为 ${domain} 申请证书（DNS-01 验证）..."
  export_dns_env
  "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "$HOME/.acme.sh/acme.sh" --register-account -m "$ACME_EMAIL" >/dev/null 2>&1 || true

  # dns_args holds acme.sh flags like "--dns dns_cf" and must word-split into two args.
  # shellcheck disable=SC2086
  issue_output="$("$HOME/.acme.sh/acme.sh" --issue -d "$domain" $dns_args 2>&1)" || {
    echo "$issue_output"
    if echo "$issue_output" | grep -qi 'rateLimited\|too many certificates'; then
      retry_after="$(echo "$issue_output" | sed -n 's/.*retry after \([^:]*UTC\).*/\1/p' | head -n1)"
      error "证书申请失败：触发 Let's Encrypt 频率限制（429）。"
      [[ -n "$retry_after" ]] && warn "可重试时间（UTC）：$retry_after"
    elif echo "$issue_output" | grep -qi 'verify error\|dns.*fail\|NXDOMAIN\|SERVFAIL'; then
      error "DNS 验证失败。请确认：1) DNS API 密钥正确 2) 域名 DNS 托管在所选服务商 3) 域名已正确解析。"
    else
      error "证书申请失败。请检查 DNS API 配置和网络连接。"
    fi
    return 1
  }

  ${SUDO} mkdir -p "${SSL_DIR}/${domain}"
  "$HOME/.acme.sh/acme.sh" --install-cert -d "$domain" \
    --key-file "${SSL_DIR}/${domain}/privkey.pem" \
    --fullchain-file "${SSL_DIR}/${domain}/fullchain.pem"

  ensure_acme_cron
  info "证书申请并安装成功（DNS-01）。"
}

_issue_cert_http() {
  # 原有的 HTTP-01 逻辑
  local domain="$1"
  local challenge_conf

  ensure_acme_location_for_domain_conf "$domain" || return 1
  challenge_conf="$(ensure_http_challenge_server "$domain")" || return 1

  if ! reload_nginx_safe; then
    cleanup_http_challenge_server "$challenge_conf"
    error "证书申请前校验失败：Nginx 配置未生效。"
    return 1
  fi

  local pre_rc=0
  if precheck_http01 "$domain"; then
    pre_rc=0
  else
    pre_rc=$?
  fi
  if (( pre_rc != 0 )); then
    if [[ $pre_rc -eq 10 ]]; then
      if ! confirm "自检存在风险，是否仍继续申请证书？"; then
        cleanup_http_challenge_server "$challenge_conf"
        reload_nginx_safe || true
        info "已取消申请。"
        return 1
      fi
      warn "你选择继续申请，将直接尝试签发。"
    else
      if has_dns_config; then
        warn "HTTP-01 自检失败，是否改用 DNS-01 方式申请？"
        if confirm "使用 DNS-01 方式？"; then
          cleanup_http_challenge_server "$challenge_conf"
          reload_nginx_safe || true
          _issue_cert_dns "$domain"
          return $?
        fi
      fi
      if ! confirm "自检失败（建议先修复），是否仍强制继续申请？"; then
        cleanup_http_challenge_server "$challenge_conf"
        reload_nginx_safe || true
        info "已取消申请。"
        return 1
      fi
      warn "你选择强制继续申请。"
    fi
  fi

  ensure_acme_installed || return 1

  note "开始为 ${domain} 申请证书（HTTP 验证）..."
  "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "$HOME/.acme.sh/acme.sh" --register-account -m "$ACME_EMAIL" >/dev/null 2>&1 || true

  local issue_output retry_after
  issue_output="$("$HOME/.acme.sh/acme.sh" --issue -d "$domain" --webroot /usr/share/nginx/html 2>&1)" || {
    echo "$issue_output"
    cleanup_http_challenge_server "$challenge_conf"
    reload_nginx_safe || true

    if echo "$issue_output" | grep -qi 'rateLimited\|too many certificates'; then
      retry_after="$(echo "$issue_output" | sed -n 's/.*retry after \([^:]*UTC\).*/\1/p' | head -n1)"
      error "证书申请失败：触发 Let's Encrypt 频率限制（429）。"
      [[ -n "$retry_after" ]] && warn "可重试时间（UTC）：$retry_after"
      warn "这是 CA 侧限制，不是你服务器或端口配置问题。"
    else
      error "证书申请失败。请确认域名已解析到本机、80 端口已放行，且没有被 CDN/防火墙拦截。"
      if has_dns_config; then
        warn "你已配置 DNS API，可前往主菜单选择 [3) 配置 DNS API] 后使用 DNS 方式申请。"
      fi
    fi
    return 1
  }

  cleanup_http_challenge_server "$challenge_conf" || return 1
  reload_nginx_safe || return 1

  ${SUDO} mkdir -p "${SSL_DIR}/${domain}"
  "$HOME/.acme.sh/acme.sh" --install-cert -d "$domain" \
    --key-file "${SSL_DIR}/${domain}/privkey.pem" \
    --fullchain-file "${SSL_DIR}/${domain}/fullchain.pem"

  ensure_acme_cron
  info "证书申请并安装成功。"
}

load_email() {
  ensure_state_dir
  if [[ -f "$EMAIL_CONF" ]]; then
    # shellcheck disable=SC1090
    . "$EMAIL_CONF"
  fi
}

save_email() {
  local email="$1"
  ensure_state_dir
  ( umask 077
    printf 'ACME_EMAIL=%q\n' "$email" > "$EMAIL_CONF"
  )
  chmod 600 "$EMAIL_CONF"
  info "邮箱已保存到：${EMAIL_CONF}"
}

ensure_acme_installed() {
  local install_script=""

  if [[ -x "$HOME/.acme.sh/acme.sh" ]]; then
    return 0
  fi

  note "未检测到 acme.sh，开始安装..."

  install_script="$(mktemp /tmp/acme-install-XXXXXX)"
  if ! curl -fsSL https://get.acme.sh -o "$install_script"; then
    cleanup_tmp_file "$install_script"
    error "acme.sh 安装脚本下载失败，请稍后重试。"
    return 1
  fi

  if ! sh "$install_script"; then
    cleanup_tmp_file "$install_script"
    error "acme.sh 安装脚本执行失败。"
    return 1
  fi

  cleanup_tmp_file "$install_script"

  if [[ ! -x "$HOME/.acme.sh/acme.sh" ]]; then
    error "acme.sh 安装失败。"
    return 1
  fi
  info "acme.sh 安装成功。"
}

ensure_acme_cron() {
  local cron_line
  cron_line="0 3 1 */2 * $HOME/.acme.sh/acme.sh --cron --home $HOME/.acme.sh >/dev/null"

  if crontab -l 2>/dev/null | grep -q 'acme.sh --cron'; then
    info "已检测到 acme.sh 自动续期任务（crontab）。"
    return 0
  fi

  # Alpine dcron: try periodic script as fallback
  if check_cmd dcron || [[ -d /etc/periodic ]]; then
    local periodic_script="/etc/periodic/monthly/acme-renew"
    if [[ -f "$periodic_script" ]]; then
      info "已检测到 acme.sh 自动续期任务（dcron periodic）。"
      return 0
    fi
    warn "未检测到 acme.sh 自动续期任务。"
    if confirm "是否一键添加自动续期任务（每月执行）？"; then
      ${SUDO} mkdir -p /etc/periodic/monthly
      ${SUDO} tee "$periodic_script" >/dev/null <<EOF
#!/bin/sh
$HOME/.acme.sh/acme.sh --cron --home $HOME/.acme.sh >/dev/null
EOF
      ${SUDO} chmod +x "$periodic_script"
      info "已添加 acme.sh 自动续期任务（/etc/periodic/monthly/acme-renew）。"
    else
      warn "你选择了不添加自动续期任务，后续需手动续期。"
    fi
    return 0
  fi

  # Standard crontab
  warn "未检测到 acme.sh 自动续期任务。"
  if confirm "是否一键添加自动续期任务（约每60天执行）？"; then
    (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
    info "已开启自动续期任务。"
  else
    warn "你选择了不添加自动续期任务，后续需手动续期。"
  fi
}

has_acme_cron_task() {
  crontab -l 2>/dev/null | grep -q 'acme.sh --cron' || \
    [[ -f /etc/periodic/monthly/acme-renew ]]
}

disable_acme_cron() {
  if crontab -l 2>/dev/null | grep -q 'acme.sh --cron'; then
    crontab -l 2>/dev/null | grep -v 'acme.sh --cron' | crontab - || true
    info "已关闭 crontab 自动续期任务。"
  fi
  if [[ -f /etc/periodic/monthly/acme-renew ]]; then
    ${SUDO} rm -f /etc/periodic/monthly/acme-renew
    info "已关闭 dcron periodic 自动续期任务。"
  fi
  if ! has_acme_cron_task; then
    :
  else
    warn "清理后仍检测到自动续期任务，请手动检查 crontab 和 periodic 目录。"
  fi
}

enable_acme_cron() {
  ensure_acme_cron
}

set_acme_email() {
  local email
  read -rp "请输入证书通知邮箱: " email
  if [[ ! "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
    error "邮箱格式不合法。请输入类似 user@example.com 的邮箱地址。"
    return 1
  fi
  save_email "$email"
}

ensure_email_interactive() {
  # 若未设置邮箱，允许在当前界面直接录入并保存
  load_email
  if [[ -n "${ACME_EMAIL:-}" ]]; then
    return 0
  fi

  warn "当前未设置 Acme 邮箱。"
  read -rp "请输入邮箱（将保存到 ${EMAIL_CONF}）: " email
  if [[ ! "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
    error "邮箱格式不合法。请输入类似 user@example.com 的邮箱地址。"
    return 1
  fi

  save_email "$email"
  # shellcheck disable=SC2034
  ACME_EMAIL="$email"
}

ensure_acme_location_for_domain_conf() {
  # 为已存在的反代配置补齐 ACME 验证 location，避免申请证书时被反代到后端
  local domain="$1"
  local -a matches
  local conf_file tmp_file

  # Collect tmp files so early-return / errors won't leak /tmp files
  local -a tmp_files=()
  # shellcheck disable=SC2154
  trap 'for f in "${tmp_files[@]}"; do rm -f "$f" 2>/dev/null || true; done' RETURN

  # Primary: match our metadata line "# domain=<domain>"
  mapfile -t matches < <(list_confs_by_meta_domain "$domain")

  # Fallback: match server_name token containing the domain (best-effort, avoids missing metadata)
  if [[ ${#matches[@]} -eq 0 ]]; then
    mapfile -t matches < <(awk -v d="$domain" '
      BEGIN{in_server=0; hasDomain=0}
      /server[[:space:]]*\{/ {in_server=1; hasDomain=0}
      in_server && index($0, "server_name") {
        # Exact token match: server_name a b c;
        line=$0
        sub(/.*server_name[[:space:]]+/, "", line)
        gsub(/;/, "", line)
        n=split(line, a, /[[:space:]]+/)
        for (i=1; i<=n; i++) {
          if (a[i] == d) {hasDomain=1}
        }
      }
      in_server && /}/ {
        if (hasDomain && !printed[FILENAME]) {
          print FILENAME
          printed[FILENAME]=1
        }
        in_server=0
      }
    ' "${CONF_DIR}"/*.conf 2>/dev/null || true)
  fi
  [[ ${#matches[@]} -gt 0 ]] || return 0

  for conf_file in "${matches[@]}"; do
    if grep -q '/\.well-known/acme-challenge/' "$conf_file"; then
      continue
    fi

    tmp_file="$(mktemp /tmp/nginxx-acme-loc-"${domain}"-XXXXXX)"
    tmp_files+=("$tmp_file")
    awk '
      BEGIN{inserted=0}
      {
        if (inserted==0 && $0 ~ /^[[:space:]]*location \/ \{/ ) {
          print "    # ACME HTTP-01 验证路径（证书申请/续期）"
          print "    location ^~ /.well-known/acme-challenge/ {"
          print "        root /usr/share/nginx/html;"
          print "        default_type \"text/plain\";"
          print "        try_files $uri =404;"
          print "    }"
          print ""
          inserted=1
        }
        print $0
      }
    ' "$conf_file" > "$tmp_file"

    if ! apply_conf_with_rollback "$tmp_file" "$conf_file"; then
      error "补充 ACME 验证路径失败，已保留原配置：${conf_file}"
      return 1
    fi
    rm -f "$tmp_file"
  done
}

ensure_http_challenge_server() {
  # 为“非80端口业务配置”补一个临时 80 验证入口，保证 HTTP-01 可达
  local domain="$1"
  local challenge_conf="${CONF_DIR}/acme-challenge-${domain}.conf"

  # 检测是否已存在“同域名 + 80监听”的配置
  if awk -v d="$domain" '
    BEGIN{in_server=0; has80=0; hasDomain=0}
    /server[[:space:]]*\{/ {in_server=1; has80=0; hasDomain=0}
    in_server && /listen[[:space:]]+80([[:space:]]|;)/ {has80=1}
    in_server && index($0, "server_name") && index($0, d) {hasDomain=1}
    in_server && /}/ {
      if (has80 && hasDomain) {print "yes"; exit 0}
      in_server=0
    }
  ' "${CONF_DIR}"/*.conf 2>/dev/null | grep -q yes; then
    echo ""
    return 0
  fi

  local tmp_challenge
  tmp_challenge="$(mktemp /tmp/.acme-challenge-"${domain}"-XXXXXX)"
  trap 'rm -f "${tmp_challenge:-}"' RETURN

  cat > "$tmp_challenge" <<EOF
server {
    listen 80;
    server_name ${domain};

    location ^~ /.well-known/acme-challenge/ {
        root /usr/share/nginx/html;
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        return 404;
    }
}
EOF

  if ! apply_conf_with_rollback "$tmp_challenge" "$challenge_conf" >&2; then
    rm -f "$tmp_challenge"
    return 1
  fi
  rm -f "$tmp_challenge"
  echo "$challenge_conf"
}

cleanup_http_challenge_server() {
  local challenge_conf="$1"
  [[ -z "$challenge_conf" ]] && return 0
  nx_transaction nx_remove_conf "$challenge_conf"
}

precheck_http01() {
  # 证书申请前自检：DNS、80监听、challenge本地命中、域名回环可达
  # 返回码：0=通过，10=软失败(可继续)，11=硬失败(不建议继续)
  local domain="$1"
  local token file_path local_url domain_url local_body domain_body

  note "开始执行 HTTP-01 申请前自检..."

  # 1) DNS 解析检查
  local dns_out
  dns_out="$(getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
  if [[ -z "$dns_out" ]]; then
    error "自检失败：域名 ${domain} 未解析到任何 IP。"
    return 11
  fi
  info "DNS解析：${dns_out}"

  # 2) 本机80监听检查（ss/netstat//proc 兜底，BusyBox 兼容）
  if ! nginx_port_listening 80; then
    error "自检失败：本机未监听 80 端口。"
    return 11
  fi

  # 3) challenge 文件本地命中检查
  token="nginxx-check-$(date +%s)-$RANDOM"
  file_path="/usr/share/nginx/html/.well-known/acme-challenge/${token}"
  ${SUDO} mkdir -p "$(dirname "$file_path")"
  echo "$token" | ${SUDO} tee "$file_path" >/dev/null

  local_url="http://127.0.0.1/.well-known/acme-challenge/${token}"
  local_body="$(curl -fsS --max-time 8 -H "Host: ${domain}" "$local_url" 2>/dev/null || true)"
  if [[ "$local_body" != "$token" ]]; then
    ${SUDO} rm -f "$file_path" 2>/dev/null || true
    error "自检失败：本机 challenge 路径未命中（${local_url}，Host: ${domain}）。"
    return 11
  fi

  # 4) 域名回环可达检查（模拟 CA 通过域名访问 80）
  domain_url="http://${domain}/.well-known/acme-challenge/${token}"
  domain_body="$(curl -fsS --max-time 10 "$domain_url" 2>/dev/null || true)"
  ${SUDO} rm -f "$file_path" 2>/dev/null || true

  if [[ "$domain_body" != "$token" ]]; then
    warn "自检警告：域名 ${domain} 的 80 回源不可达或返回内容不匹配。"
    warn "这可能是网络/回环差异导致的误判。"
    warn "请检查云安全组/防火墙/NAT/CDN 对 80 端口的放行。"
    return 10
  fi

  info "HTTP-01 自检通过。"
  return 0
}

issue_cert() {
  local domain cert_mode
  load_email

  if [[ -z "${ACME_EMAIL:-}" ]]; then
    error "未设置邮箱。请先在证书管理里执行 [1) 设置邮箱]。"
    return 1
  fi

  read -rp "请输入要申请证书的域名: " domain
  if ! valid_domain "$domain"; then
    error "域名格式不合法。请输入可签发证书的域名，例如 example.com。"
    return 1
  fi

  cert_mode="$(select_cert_mode_interactive)"

  if [[ "$cert_mode" == "dns" ]]; then
    _issue_cert_dns "$domain"
  else
    _issue_cert_http "$domain"
  fi
}

issue_cert_for_domain() {
  local domain="$1"
  local cert_mode="${2:-}"
  load_email

  if [[ -z "${ACME_EMAIL:-}" ]]; then
    error "未设置邮箱，无法自动申请证书。请先在证书管理里设置邮箱。"
    return 1
  fi

  if [[ -z "$cert_mode" ]]; then
    cert_mode="$(detect_cert_mode)"
  fi

  if [[ "$cert_mode" == "dns" ]]; then
    if ! has_dns_config; then
      error "DNS-01 需要配置 DNS API Token，请先设置。"
      return 1
    fi
    info "使用 DNS-01 方式为 ${domain} 申请证书..."
    _issue_cert_dns "$domain"
  else
    _issue_cert_http "$domain"
  fi
}

cert_list_action_menu() {
  local domain="$1"
  while true; do
    clear
    echo "====== 证书操作：${domain} ======"
    echo "1) 重新申请"
    echo "2) 启停续期"
    echo "3) 删除证书"
    echo "0) 返回上一级"
    echo "============================="
    read -rp "请选择: " c

    case "$c" in
      1)
        load_email
        if [[ -z "${ACME_EMAIL:-}" ]]; then
          if ! ensure_email_interactive; then
            error "邮箱未设置，无法重新申请。"
            pause
            return 0
          fi
        fi
        run_menu_action issue_cert_for_domain "$domain"
        pause
        return 0
        ;;
      2)
        if has_acme_cron_task; then
          if confirm "当前续期任务已开启，是否关闭？"; then
            disable_acme_cron
          fi
        else
          if confirm "当前续期任务未开启，是否开启？"; then
            enable_acme_cron
          fi
        fi
        pause
        return 0
        ;;
      3)
        local -a refs
        mapfile -t refs < <(cert_referenced_confs "$domain")
        if [[ ${#refs[@]} -gt 0 ]]; then
          warn "证书 ${domain} 仍被以下 Nginx 配置引用，已拒绝删除："
          local ref
          for ref in "${refs[@]}"; do
            warn "  - ${ref}"
          done
          warn "请先停用对应站点 HTTPS 或手动移除证书引用，再删除证书。"
          pause
          return 0
        fi

        if ! confirm "确认删除证书 ${domain} ?"; then
          info "已取消。"
          pause
          return 0
        fi

        local ssl_backup="" acme_backup="" acme_ecc_backup=""
        ssl_backup="$(mktemp -d /tmp/nginxx-cert-"${domain}"-XXXXXX)"
        if [[ -d "${SSL_DIR}/${domain}" ]]; then
          ${SUDO} cp -a "${SSL_DIR}/${domain}" "${ssl_backup}/ssl" 2>/dev/null || true
        fi
        if [[ -d "$HOME/.acme.sh/${domain}" ]]; then
          acme_backup="${ssl_backup}/acme"
          cp -a "$HOME/.acme.sh/${domain}" "$acme_backup" 2>/dev/null || true
        fi
        if [[ -d "$HOME/.acme.sh/${domain}_ecc" ]]; then
          acme_ecc_backup="${ssl_backup}/acme_ecc"
          cp -a "$HOME/.acme.sh/${domain}_ecc" "$acme_ecc_backup" 2>/dev/null || true
        fi

        if [[ -x "$HOME/.acme.sh/acme.sh" ]]; then
          "$HOME/.acme.sh/acme.sh" --remove -d "$domain" >/dev/null 2>&1 || true
        fi
        rm -rf "$HOME/.acme.sh/${domain}" "$HOME/.acme.sh/${domain}_ecc" 2>/dev/null || true
        ${SUDO} rm -rf "${SSL_DIR}/${domain}" 2>/dev/null || true

        if ! nginx_test; then
          warn "删除证书后 nginx -t 失败，正在恢复证书文件。"
          if [[ -d "${ssl_backup}/ssl" ]]; then
            ${SUDO} mkdir -p "$SSL_DIR"
            ${SUDO} cp -a "${ssl_backup}/ssl" "${SSL_DIR}/${domain}"
          fi
          if [[ -n "$acme_backup" && -d "$acme_backup" ]]; then
            mkdir -p "$HOME/.acme.sh"
            cp -a "$acme_backup" "$HOME/.acme.sh/${domain}" 2>/dev/null || true
          fi
          if [[ -n "$acme_ecc_backup" && -d "$acme_ecc_backup" ]]; then
            mkdir -p "$HOME/.acme.sh"
            cp -a "$acme_ecc_backup" "$HOME/.acme.sh/${domain}_ecc" 2>/dev/null || true
          fi
          rm -rf "$ssl_backup" 2>/dev/null || true
          error "证书删除已回滚。请检查 nginx -t 输出后重试。"
          ${SUDO} nginx -t || true
          pause
          return 1
        fi

        rm -rf "$ssl_backup" 2>/dev/null || true
        info "证书已删除：${domain}"
        pause
        return 0
        ;;
      0) return 0 ;;
      *) warn "无效输入。请输入 0-3 之间的菜单编号。"; pause ;;
    esac
  done
}

cert_list_menu() {
  if [[ ! -x "$HOME/.acme.sh/acme.sh" ]]; then
    warn "未检测到 acme.sh，请先申请证书。"
    pause
    return 0
  fi

  local -a certs
  local domain idx renew_status
  mapfile -t certs < <(
    "$HOME/.acme.sh/acme.sh" --list 2>/dev/null | awk 'NR>1 && NF>0 {print $1}'
  )

  if [[ ${#certs[@]} -eq 0 ]]; then
    warn "当前未发现已签发证书。你可以先去 [2) 申请证书]。"
    return 0
  fi

  while true; do
    clear
    echo "========== 证书列表 =========="
    if has_acme_cron_task; then
      renew_status="已开启"
    else
      renew_status="未开启"
    fi

    for i in "${!certs[@]}"; do
      echo "$((i+1))) ${certs[$i]}  [续期任务: ${renew_status}]"
    done
    echo "0) 返回上一级"
    echo "============================"
    read -rp "请输入证书编号: " idx

    if [[ "$idx" == "0" ]]; then
      return 0
    fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#certs[@]} )); then
      warn "无效编号。请输入证书列表中存在的编号。"
      pause
      continue
    fi

    domain="${certs[$((idx-1))]}"
    cert_list_action_menu "$domain"

    # 操作后刷新证书列表
    mapfile -t certs < <(
      "$HOME/.acme.sh/acme.sh" --list 2>/dev/null | awk 'NR>1 && NF>0 {print $1}'
    )
    if [[ ${#certs[@]} -eq 0 ]]; then
      warn "当前已无证书。"
      pause
      return 0
    fi
  done
}

enable_https_for_domain() {
  enable_https_from_config_list
}

