#!/usr/bin/env bash
# Sourced after nx.sh's legacy helpers. Mutations run inside nx_transaction.
# Policy metadata: access_policy=inherit|strict|open; access_default=<socket>[,...].
# Socket identity is an IP literal plus port (wildcard IPv4 is 0.0.0.0:PORT).

domain_only_state_is_enabled() {
  [[ -f "$DOMAIN_ONLY_STATE" ]] && grep -qx 'DOMAIN_ONLY=1' "$DOMAIN_ONLY_STATE"
}

nx_access_error() { error "访问策略：$*" >&2; return 1; }

# A small lexical parser preserves every byte outside our marked insertions.
# It understands comments, quoted strings, escapes and nested blocks. Ambiguous
# includes/listeners/names are rejected instead of guessing or rebuilding a site.
# scan output: server-index|socket|ssl|default|names
nx_access_parse() {
  local file="$1" mode="${2:-scan}" strict="${3:-0}" defaults="${4:-}"
  awk -v mode="$mode" -v strict="$strict" -v defaults="$defaults" '
  function fail(s) { print "access policy: " FILENAME ": " s > "/dev/stderr"; bad=1; exit 1 }
  function socket(s, p,a,n,i) {
    if(s ~ /^[0-9]+$/) s="0.0.0.0:" s
    sub(/^\*:/,"0.0.0.0:",s)
    if(s !~ /^([0-9]+\.)+[0-9]+:[0-9]+$/ && s !~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) fail("unsupported listen address " s)
    p=s; sub(/^.*:/,"",p); if(p+0<1 || p+0>65535) fail("invalid listen port")
    if(s !~ /^\[/) { a=s; sub(/:[0-9]+$/,"",a); n=split(a,t,"."); if(n!=4) fail("invalid IPv4 address"); for(i=1;i<=4;i++) if(t[i]+0>255) fail("invalid IPv4 address") }
    return tolower(s)
  }
  function directive(end,    x,n,a,i,s,ssl,def,k) {
    x=token; gsub(/^[ \t\r\n]+|[ \t\r\n]+$/,"",x); token=""
    if(end=="{") {
      depth++; if(x=="server" && depth==1) {srv++; active=srv; start[srv]=pos; count[srv]=0}
      else if(depth==1 && mode=="transform") fail("non-server top-level block")
      return
    }
    if(end=="}") { if(active && depth==1) {finish[active]=pos; active=0}; depth--; if(depth<0) fail("unbalanced braces"); return }
    if(!active || depth!=1) { if(mode=="transform" && depth==0 && x!="") fail("top-level directive cannot be safely inspected"); return }
    n=split(x,a,/[ \t\r\n]+/)
    if(a[1]=="include") fail("server-level include cannot be safely inspected")
    if(a[1]=="listen") {
      if(n<2) fail("empty listen")
      s=socket(a[2]); ssl=0; def=0
      for(i=3;i<=n;i++) {if(a[i]=="ssl") ssl=1; if(a[i]=="default_server" || a[i]=="default") def=1; if(a[i]=="quic" || a[i]=="udp" || a[i]=="ipv6only=off") fail("unsupported listener option " a[i])}
      k=++listeners; owner[k]=active; sock[k]=s; tls[k]=ssl; existing[k]=def; count[active]++; if(ssl) secure[active]=1
      # Insert only our flag at the semicolon; never remove user default flags.
      if(index("," defaults ",","," s ",")) {if(def) fail("requested default already has an unmanaged default flag"); insertion[pos]=" default_server # nx-access-default\n"; selected[s]++}
    }
    if(a[1]=="server_name") {
      if(names[active]!="") fail("multiple server_name directives")
      for(i=2;i<=n;i++) {
        if(strict && a[i] ~ /^[0-9.]+$/) fail("strict policy requires DNS names, not IP addresses")
        if(strict && a[i] !~ /^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*\.?$/) fail("strict policy requires literal DNS server_name aliases")
        names[active]=names[active] (i==2?"":" ") tolower(a[i])
      }
    }
  }
  /^[ \t]*# nx-access-begin$/ {sub(/\n$/, "", text); skip=1; next}
  /^[ \t]*# nx-access-end$/ {if(!skip) fail("orphan policy marker"); skip=0; next}
  {if(skip) next; line=$0; sub(/ default_server # nx-access-default$/, "",line); text=text line "\n"}
  END {
    if(bad) exit 1; if(skip) fail("unterminated policy marker")
    depth=0; quote=""; comment=0; escape=0; token=""
    for(pos=1;pos<=length(text);pos++) {
      c=substr(text,pos,1)
      if(comment) {if(c=="\n") {comment=0; token=token " "}; continue}
      if(escape) {token=token c; escape=0; continue}
      if(c=="\\") {token=token c; escape=1; continue}
      if(quote!="") {token=token c; if(c==quote) quote=""; continue}
      if(c=="\047" || c=="\042") {quote=c; token=token c; continue}
      if(c=="#") {comment=1; continue}
      if(c=="$" && substr(text,pos+1,1)=="{") {
        closevar=index(substr(text,pos+2),"}"); if(!closevar) fail("unterminated variable")
        token=token substr(text,pos,closevar+2); pos+=closevar+1; continue
      }
      if(c=="{" || c=="}" || c==";") directive(c); else token=token c
    }
    if(depth || quote!="" || escape) fail("incomplete configuration")
    if(!srv && mode=="transform") fail("no server block")
    for(i=1;i<=srv;i++) {
      if(!count[i]) fail("implicit listen is not supported")
      if(strict && names[i]=="") fail("strict policy requires server_name")
    }
    n=split(defaults,ds,","); for(i=1;i<=n;i++) if(ds[i]!="" && selected[ds[i]]!=1) fail("default socket must identify exactly one server: " ds[i])
    if(mode=="scan") {for(i=1;i<=listeners;i++) print owner[i] "|" sock[i] "|" tls[i] "|" existing[i] "|" names[owner[i]]; exit}
    if(strict) for(i=1;i<=srv;i++) {
      n=split(names[i],ns," "); pattern=""; for(j=1;j<=n;j++) {sub(/\.$/,"",ns[j]); gsub(/\./,"\\.",ns[j]); pattern=pattern (j==1?"":"|") ns[j]}
      # $http_host proves Host was actually supplied; $host alone falls back to server_name.
      guard="\n    # nx-access-begin\n    if ($http_host !~* \"^(" pattern ")\\.?(:[0-9]+)?$\") { return 444; }\n"
      guard=guard "    if ($host !~* \"^(" pattern ")$\") { return 444; }\n"
      if(secure[i]) {
        # Canonicalize each accepted SNI alias to its literal lowercase name.
        # Unlike regex backreferences this remains case-insensitive for SNI.
        guard=guard "    set $nx_access_sni \"\";\n"
        for(j=1;j<=n;j++) {
          canonical=ns[j]; gsub(/\\\./,".",canonical)
          guard=guard "    if ($ssl_server_name ~* \"^" ns[j] "\\.?$\") { set $nx_access_sni " canonical "; }\n"
        }
        guard=guard "    if ($nx_access_sni != $host) { return 444; }\n"
      }
      guard=guard "    # nx-access-end\n"
      insertion[start[i]+1]=guard insertion[start[i]+1]
    }
    for(pos=1;pos<=length(text);pos++) printf "%s%s", insertion[pos], substr(text,pos,1)
  }' "$file"
}

nx_access_site_policy() {
  local p
  [[ "$(grep -c '^# access_policy=' "$1" || true)" -le 1 ]] || { nx_access_error "重复策略元数据"; return 1; }
  p="$(conf_meta_get "$1" access_policy)"
  case "$p" in ''|inherit) if domain_only_state_is_enabled; then echo strict; else echo open; fi;; strict|open) echo "$p";; *) nx_access_error "无效 access_policy: $p";; esac
}

nx_access_metadata() {
  local file="$1" key="$2" value="$3" tmp
  [[ -f "$file" && ! -L "$file" ]] || return 1
  tmp="$(mktemp)" || return 1
  if awk -v k="$key" -v v="$value" 'index($0,"# " k "=")==1 {next} {print} END {print "# " k "=" v}' "$file" > "$tmp"; then
    ${SUDO:-} tee "$file" < "$tmp" >/dev/null || { rm -f "$tmp"; return 1; }
  else rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
}

nx_access_set_policy_files() {
  case "$2" in inherit|strict|open) ;; *) return 1;; esac
  nx_access_metadata "$1" access_policy "$2"
}
nx_access_set_policy() { nx_transaction nx_access_set_policy_files "$@"; }
nx_access_set_default_files() {
  [[ "$2" != *$'\n'* && "$2" != *$'\r'* ]] || return 1
  nx_access_metadata "$1" access_default "$2"
}
nx_access_set_default() { nx_transaction nx_access_set_default_files "$@"; }

# Collect transformed files before publishing any of them. The caller transaction
# provides rollback for publication errors and nginx validation/reload failures.
nx_access_sync_files() {
  local stage file policy defaults name rows socket ssl def _server _names line
  local -A required=() tls=() plain=() occupied=() managed=()
  local -a files=()
  stage="$(mktemp -d)" || return 1
  mapfile -t files < <(list_managed_conf_files 0)
  for file in "${files[@]}"; do
    [[ ! -L "$file" ]] || { rm -rf "$stage"; nx_access_error "不修改符号链接 $file"; return 1; }
    name="$(basename "$file")"; managed["$file"]=1
    policy="$(nx_access_site_policy "$file")" || { rm -rf "$stage"; return 1; }
    defaults="$(conf_meta_get "$file" access_default)"
    if ! nx_access_parse "$file" transform "$([[ "$policy" == strict ]] && echo 1 || echo 0)" "$defaults" > "$stage/$name"; then rm -rf "$stage"; return 1; fi
    # Scan the generated default flags (strip marker comment, not flag).
    sed 's/ # nx-access-default//' "$stage/$name" > "$stage/scan"
    rows="$(nx_access_parse "$stage/scan")" || { rm -rf "$stage"; return 1; }
    while IFS='|' read -r _server socket ssl def _names; do
      [[ -n "$socket" ]] || continue
      [[ "$policy" == strict ]] && required["$socket"]=1
      if [[ "$ssl" == 1 ]]; then tls["$socket"]=1; else plain["$socket"]=1; fi
      if [[ "$def" == 1 ]]; then
        if [[ -n "${occupied[$socket]:-}" ]]; then rm -rf "$stage"; nx_access_error "重复 default_server: $socket"; return 1; fi
        occupied["$socket"]="$file"
      fi
    done <<< "$rows"
  done
  # Existing default servers, including unmanaged sites, own exactly their socket.
  for file in "$CONF_DIR"/*.conf; do
    [[ -f "$file" && "$file" != "$(domain_only_conf_path)" && -z "${managed[$file]:-}" ]] || continue
    # Non-server helper files (maps etc.) have no listen directives.
    if ! grep -qE '(^|[;{}[:space:]])listen[[:space:]]' "$file"; then continue; fi
    rows="$(nx_access_parse "$file")" || { rm -rf "$stage"; return 1; }
    while IFS='|' read -r _server socket ssl def _names; do
      [[ -n "$socket" ]] || continue
      if [[ "$ssl" == 1 ]]; then tls["$socket"]=1; else plain["$socket"]=1; fi
      if [[ "$def" == 1 ]]; then
        if [[ -n "${occupied[$socket]:-}" ]]; then rm -rf "$stage"; nx_access_error "与现有 default_server 冲突: $socket"; return 1; fi
        occupied["$socket"]="$file"
      fi
    done <<< "$rows"
  done
  printf '# managed_by=Nginx-X\n# nx-access-catchall=1\n' > "$stage/catchall"
  local -a sorted_sockets=()
  if ((${#required[@]})); then mapfile -t sorted_sockets < <(printf '%s\n' "${!required[@]}" | LC_ALL=C sort); fi
  for socket in "${sorted_sockets[@]}"; do
    [[ -z "${occupied[$socket]:-}" ]] || continue
    {
      echo 'server {'
      line="$socket"; [[ "$line" == 0.0.0.0:* ]] && line="${line#*:}"
      if [[ -n "${tls[$socket]:-}" ]]; then
        echo "    listen $line ssl default_server;"
        if [[ -z "${plain[$socket]:-}" ]] && nginx_supports_ssl_reject_handshake; then
          echo '    ssl_reject_handshake on;'
        else
          # Certificate must live inside CONF_DIR so the transaction owns it.
          echo "    ssl_certificate \"$CONF_DIR/.nx-access-cert.pem\";"
          echo "    ssl_certificate_key \"$CONF_DIR/.nx-access-key.pem\";"
          : > "$stage/need-cert"
        fi
      else echo "    listen $line default_server;"; fi
      echo '    server_name _;'
      echo '    return 444;'
      echo '}'
    } >> "$stage/catchall"
  done
  if [[ -f "$stage/need-cert" && ( ! -f "$CONF_DIR/.nx-access-cert.pem" || ! -f "$CONF_DIR/.nx-access-key.pem" ) ]]; then
    if ! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=nx-access -keyout "$stage/key" -out "$stage/cert" >/dev/null 2>&1; then rm -rf "$stage"; return 1; fi
    if ! ${SUDO:-} install -m 600 "$stage/key" "$CONF_DIR/.nx-access-key.pem" || ! ${SUDO:-} install -m 644 "$stage/cert" "$CONF_DIR/.nx-access-cert.pem"; then rm -rf "$stage"; return 1; fi
  fi
  for file in "${files[@]}"; do
    # Preserve mode and ownership of existing site files.
    if ! cmp -s "$file" "$stage/$(basename "$file")"; then
      ${SUDO:-} tee "$file" < "$stage/$(basename "$file")" >/dev/null || { rm -rf "$stage"; return 1; }
    fi
  done
  if grep -q '^server {' "$stage/catchall"; then
    ${SUDO:-} install -m 644 "$stage/catchall" "$(domain_only_conf_path)" || { rm -rf "$stage"; return 1; }
  else ${SUDO:-} rm -f "$(domain_only_conf_path)" || { rm -rf "$stage"; return 1; }; fi
  rm -rf "$stage"
}

nx_access_global_files() {
  mkdir -p "$(dirname "$DOMAIN_ONLY_STATE")" || return 1
  printf 'DOMAIN_ONLY=%s\n' "$1" > "$DOMAIN_ONLY_STATE" && chmod 600 "$DOMAIN_ONLY_STATE"
}
domain_only_enable() {
  nx_transaction nx_access_global_files 1 || return 1
  info '全局继承策略已设为严格域名校验（Host；TLS 同时校验 SNI）。'
  domain_only_warn_exposed_ports
}
domain_only_disable() { nx_transaction nx_access_global_files 0; }
nx_access_noop() { :; }
domain_only_sync() { nx_transaction nx_access_noop; }
domain_only_rebuild_if_enabled() { domain_only_sync; }
# apply_conf_with_rollback already syncs within its transaction.
domain_only_after_apply() { :; }

nx_site_access_menu() {
  local file="$1" c
  [[ -f "$file" ]] || file="$CONF_DIR/$file"
  echo "站点: $(basename "$file")；有效策略: $(nx_access_site_policy "$file")"
  echo '1) 继承全局  2) 严格 Host / SNI  3) 开放（仍按 Nginx server_name 路由）  0) 返回'
  read -rp '请选择: ' c || return 1
  case "$c" in 1) nx_access_set_policy "$file" inherit;; 2) nx_access_set_policy "$file" strict;; 3) nx_access_set_policy "$file" open;; 0) return 0;; *) return 1;; esac
}

nx_default_site_menu() {
  local -a files=() sockets=()
  local i choice file rows socket defaults
  mapfile -t files < <(list_managed_conf_files 0)
  for i in "${!files[@]}"; do echo "$((i+1))) $(basename "${files[$i]}")"; done
  echo '0) 返回'
  read -rp '默认站点编号: ' choice || return 1
  [[ "$choice" == 0 ]] && return 0
  [[ "$choice" =~ ^[1-9][0-9]*$ ]] && ((choice<=${#files[@]})) || return 1
  file="${files[$((choice-1))]}"
  rows="$(nx_access_parse "$file")" || return 1
  mapfile -t sockets < <(cut -d '|' -f2 <<< "$rows" | sort -u)
  for i in "${!sockets[@]}"; do echo "$((i+1))) ${sockets[$i]}"; done
  echo '0) 清除此站点的显式默认设置'
  echo '默认站点会接收该监听地址上未匹配的请求；严格策略仍拒绝无效 Host / SNI。'
  read -rp '选择监听地址: ' choice || return 1
  if [[ "$choice" == 0 ]]; then nx_access_set_default "$file" ''; return; fi
  [[ "$choice" =~ ^[1-9][0-9]*$ ]] && ((choice<=${#sockets[@]})) || return 1
  socket="${sockets[$((choice-1))]}"
  defaults="$(conf_meta_get "$file" access_default)"
  if [[ ",$defaults," != *",$socket,"* ]]; then defaults="${defaults:+$defaults,}$socket"; fi
  nx_access_set_default "$file" "$defaults"
}

domain_only_menu() {
  local c
  while true; do
    echo '访问策略：全局规则适用于选择“继承”的站点；每个站点可单独覆盖。'
    if domain_only_state_is_enabled; then echo '全局：严格'; else echo '全局：开放'; fi
    echo '1) 全局严格  2) 全局开放  3) 设置默认站点  0) 返回'
    read -rp '请选择: ' c || return 1
    case "$c" in 1) run_menu_action domain_only_enable; pause;; 2) run_menu_action domain_only_disable; pause;; 3) run_menu_action nx_default_site_menu; pause;; 0) return 0;; *) warn '无效输入。';; esac
  done
}

# Compatibility for the diagnostics page: ports only, parsed from exact sockets.
domain_only_collect_ports() {
  local file rows socket ssl
  while IFS= read -r file; do
    rows="$(nx_access_parse "$file")" || return 1
    while IFS='|' read -r _ socket ssl _ _; do
      [[ -n "$socket" ]] || continue
      if [[ "$ssl" == 1 ]]; then printf 'ssl %s\n' "${socket##*:}"; else printf 'plain %s\n' "${socket##*:}"; fi
    done <<< "$rows"
  done < <(list_managed_conf_files 0)
}
