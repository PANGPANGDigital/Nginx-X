#!/usr/bin/env bash
# One mutation, derived access rules, config validation and reload form a unit.
# Directory-wide snapshots retain modes/owners and include disabled sites.
nx_transaction() {
  local snapshot rc=0 state_existed=0
  [[ -n "$CONF_DIR" && "$CONF_DIR" != / && -d "$CONF_DIR" && ! -L "$CONF_DIR" ]] || { error "配置目录必须是明确的普通目录。"; return 1; }
  snapshot="$(mktemp -d /tmp/nginxx-transaction-XXXXXX)" || return 1
  if ! ${SUDO} cp -a "$CONF_DIR" "$snapshot/conf"; then
    rm -rf "$snapshot"
    return 1
  fi
  if [[ -f "$DOMAIN_ONLY_STATE" ]]; then
    state_existed=1
    if ! ${SUDO} cp -a "$DOMAIN_ONLY_STATE" "$snapshot/state"; then
      ${SUDO} rm -rf "$snapshot"
      return 1
    fi
  fi
  if "$@" && nx_access_sync_files && reload_nginx_safe; then
    ${SUDO} rm -rf "$snapshot"
    return 0
  fi
  error "配置应用失败，正在恢复本次操作前的配置与访问策略。"
  # Only this configured directory is restored; never touch nginx system paths.
  local path
  for path in "$CONF_DIR"/* "$CONF_DIR"/.[!.]* "$CONF_DIR"/..?*; do
    [[ -e "$path" || -L "$path" ]] || continue
    ${SUDO} rm -rf -- "$path" || rc=1
  done
  ${SUDO} cp -a "$snapshot/conf/." "$CONF_DIR/" || rc=1
  if (( state_existed )); then
    ${SUDO} cp -a "$snapshot/state" "$DOMAIN_ONLY_STATE" || rc=1
  else
    ${SUDO} rm -f "$DOMAIN_ONLY_STATE" || rc=1
  fi
  if (( rc )); then
    error "恢复文件失败；备份保留在 ${snapshot}，请立即检查。"
    return 1
  fi
  ${SUDO} rm -rf "$snapshot"
  if ! reload_nginx_safe; then
    error "磁盘配置已恢复，但旧配置重载失败；请检查 Nginx 服务状态。"
  fi
  return 1
}

nx_write_conf() {
  local tmp="$1" target="$2" old="${3:-}"
  if [[ -n "$old" && "$old" != "$target" && -e "$target" ]]; then
    error "目标配置已存在，拒绝覆盖：${target}"
    return 1
  fi
  if [[ -n "$old" && -f "$old" ]]; then
    local metadata key value
    metadata="$(mktemp /tmp/nginxx-metadata-XXXXXX)" || return 1
    sed '/^# access_policy=/d; /^# access_default=/d' "$tmp" > "$metadata" || { rm -f "$metadata"; return 1; }
    for key in access_policy access_default; do
      value="$(conf_meta_get "$old" "$key")"
      if [[ -n "$value" ]]; then printf '\n# %s=%s\n' "$key" "$value" >> "$metadata"; fi
    done
    install_managed_file "$metadata" "$target" || { rm -f "$metadata"; return 1; }
    rm -f "$metadata"
  else
    install_managed_file "$tmp" "$target" || return 1
  fi
  ensure_ssl_directives_present "$target" || return 1
  if [[ -n "$old" && "$old" != "$target" ]]; then
    ${SUDO} rm -f "$old" || return 1
  fi
}

apply_conf_with_rollback() {
  local target="$2" backup="" existed=0 rc=0
  # Callers may edit an imported file outside CONF_DIR. Include that target too.
  if [[ "$(dirname "$target")" != "$CONF_DIR" ]]; then
    backup="$(mktemp /tmp/nginxx-target-XXXXXX)" || return 1
    if [[ -e "$target" ]]; then
      existed=1
      ${SUDO} cp -a "$target" "$backup" || { rm -f "$backup"; return 1; }
    fi
  fi
  nx_transaction nx_write_conf "$@" || rc=1
  if [[ -n "$backup" ]]; then
    if (( rc )); then
      if (( existed )); then ${SUDO} cp -a "$backup" "$target"; else ${SUDO} rm -f "$target"; fi
      reload_nginx_safe >/dev/null 2>&1 || true
    fi
    ${SUDO} rm -f "$backup"
  fi
  return "$rc"
}

nx_move_conf() {
  [[ -f "$1" && ! -e "$2" ]] || { error "源配置不存在或目标已存在。"; return 1; }
  ${SUDO} mv "$1" "$2"
}

enable_conf() {
  local file="${1:-}"
  [[ "$file" == *.conf.bak ]] || { error "只能启用 .conf.bak 站点。"; return 1; }
  nx_transaction nx_move_conf "$CONF_DIR/$file" "$CONF_DIR/${file%.bak}" || return 1
  info "已启用：${file%.bak}"
}

disable_conf() {
  local file="${1:-}"
  [[ "$file" == *.conf ]] || { error "只能停用 .conf 站点。"; return 1; }
  nx_transaction nx_move_conf "$CONF_DIR/$file" "$CONF_DIR/$file.bak" || return 1
  info "已停用：${file}"
}

delete_conf() {
  local file="${1:-}"
  [[ -n "$file" && -f "$CONF_DIR/$file" ]] || return 1
  confirm "确认永久删除 ${file} ?" || return 0
  nx_transaction nx_remove_conf "$CONF_DIR/$file" || return 1
  info "已删除：${file}"
}

edit_conf_manual() {
  local file="${1:-}" tmp
  [[ -n "$file" && -f "$CONF_DIR/$file" ]] || return 1
  tmp="$(mktemp /tmp/nginxx-edit-XXXXXX)" || return 1
  if ! ${SUDO} cp "$CONF_DIR/$file" "$tmp" || ! run_editor "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mark_conf_manual_edited "$tmp" || ! apply_conf_with_rollback "$tmp" "$CONF_DIR/$file"; then
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
  info "配置已编辑并生效：${file}"
}

nx_site_https_toggle() {
  local file="$1" domain
  [[ "$file" == *.conf ]] || { error "请先启用站点。"; return 1; }
  domain="$(extract_domain_from_conf "$file")"
  if conf_https_enabled "$file"; then
    disable_https_for_conf_file "$domain" "$file"
  else
    ensure_cert_for_domain_interactive "$domain" || return 1
    enable_https_for_conf_file "$domain" "$file"
  fi
}

nx_remove_conf() { ${SUDO} rm -f "$1"; }
