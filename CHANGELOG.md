# Changelog

---

## [3.0.0] - 2026-10-02

### Changed
- 将“仅域名访问”及默认入口管理统一收进单站点操作菜单，移除配置管理中的独立全局入口；保留已有继承策略的实际行为。

### Added
- 全局/站点域名访问策略（继承、严格、显式开放），按监听地址和端口设置默认站点并检测冲突。
- 严格 Host 和 TLS SNI 一致校验，支持字面别名、大小写/末尾点归一化，拒绝缺失 Host/SNI 和跨别名错配。
- 配置列表显示域名、监听地址、HTTPS、策略、状态，增加站点访问限制、HTTPS 和健康检查快捷入口。
- 模块化模板、证书、事务、访问策略和 HTTPS 代码；安装时打包为完整单文件，避免更新版本混用。
- 真实隔离 Nginx 请求测试与故障注入回归，覆盖共享 socket、ACME、IPv4/IPv6、默认选择和重载回滚。

### Fixed
- 启用、停用、删除、编辑、修改与派生拒绝配置组成一次校验/重载事务，失败向调用方传播并恢复配置和状态。
- 最后站点移除时清理拒绝监听；具体 IPv6 地址不再扩大成通配地址。
- HTTPS 开关保留自定义配置、别名和现有 IPv6；HTTP-01 challenge 不再被服务器级跳转覆盖。
- “隐藏IP”更名为“域名访问限制”，明确默认站点和开放策略的例外语义。

## [2.1.0] - 2026-09-27

### Added
- **仅域名访问（隐藏IP）**：「配置管理」新增一键开关（`6) 仅域名访问（隐藏IP）`）。开启后生成 catch-all 配置（`conf.d/00-nx-domain-only.conf`），用 IP 或未配置域名访问 Nginx 监听端口一律返回 444 直接断开，限制未匹配域名访问（不隐藏 IP）。覆盖全部受管监听端口，站点新增/停用/删除/修改时自动同步；HTTPS 端口优先用 `ssl_reject_handshake`（nginx ≥ 1.19.4），旧版本回退自签占位证书；已存在 `default_server` 的端口自动跳过；全程 `nginx -t` 校验、失败自动回滚。

### Fixed
- **LilyEmby 方案非标端口修复**：当反代监听端口非 443（如 443 被占用改用 8443）时，`sub_filter` / `proxy_redirect` 的重写目标现在会带上端口后缀（`https://域名:端口/sN`）。此前重写目标丢失端口，指向默认 443，客户端在非标端口访问时拿到不可达地址，导致播放大流量绕过反代直连源推流域名（issue #6）。标准 443 端口行为不变。
- 配置写入统一使用 `0644` 权限，避免 `mktemp` 的 `0600` 权限和调用用户属主被复制到 Nginx 配置或 `/etc/resolv.conf`。
- WebSocket map、ACME location 和普通配置在校验或重载失败时均会恢复原文件。
- HTTPS 启用/停用会保留内部反代的 `backend_port` 元数据，避免后续修改时回退到默认端口。
- DNS API 密钥和 ACME 邮箱使用 shell 安全转义持久化，避免特殊字符在加载时被解释执行。
- 移除 `grep -P`、`awk ENDFILE/nextfile` 等 BusyBox 不兼容用法，并为端口检测增加 `netstat` 回退。
- 修正 ACME 续期任务残留提示和实时状态 QPS 的 5 秒采样换算。

### Security
- 上游 URL 拒绝 `$`，避免 heredoc 生成配置时发生 shell 变量展开。

---

## [2.0.0] - 2026-07-02

### Added
- **Alpine Linux / OpenWrt 兼容**：BusyBox 适配（`grep`/`sed`/`awk`/`mktemp` 模板），包管理器自动检测（apt / yum / dnf / apk / opkg），Nginx 配置目录自动识别（`http.d` vs `conf.d`），Nginx 安装完成后重新检测 `CONF_DIR`
- **OpenRC 支持**：`rc-service` / `rc-update` 分支，Alpine/dcron periodic 自动续期回退
- **DNS-01 证书验证**：支持 Cloudflare / DNSPod / 阿里云 / HE.net / GoDaddy / 华为云 / AWS Route53 / Google Cloud
- **DNS API 配置管理菜单**：独立管理 DNS 服务商 Token
- **交互式证书验证方式选择**：HTTP-01 / DNS-01 二选一，适配 NAT / 无 80 端口场景；HTTP-01 挑战失败时自动提示切换 DNS-01
- **系统 DNS 设置菜单**：内置常见 DNS 供应商（Google / Cloudflare / 阿里 / 腾讯 / 自定义）
- **脚本自更新**：主菜单一键 `git pull` 拉取最新代码
- OpenSSL 依赖自动安装 + acme.sh 引导安装
- 安装时根据系统 locale 自动切换中英文提示（仅当当前 locale 为中文时才安装中文语言包）
- 版本号后附代码修改日期 `(YYYY-MM-DD)`

### Fixed
- 修复 `select_cert_mode_interactive` 中 `warn`/`error` 输出到 stdout 被 `$()` 捕获，导致选择 DNS-01 后误触发 HTTP-01 自检
- 未安装 Nginx 时 WebSocket map 检查不再报错
- WebSocket map 注入时 grep 转义修正；当 `conf.d` 位于 nginx.conf http 块之外时，直接向 nginx.conf 注入 map
- 证书模式菜单改用 ASCII 字符，避免 Alpine 编码异常
- BusyBox 兼容：`mktemp` 模板中的 `XXXXXX` 一律放在末尾

### Security
- DNS API 密钥文件写入前设置 `umask 077`，写入后 `chmod 600`，避免明文密钥被同机其他用户读取
- 系统 DNS 设置检测 `systemd-resolved` / `resolvconf` / `NetworkManager` 是否托管 `/etc/resolv.conf`，托管时二次确认后再覆盖；处理软链场景

### Changed
- 更新脚本菜单：优先使用当前脚本所在 Git 仓库目录，其次回退到 `/opt/Nginx-X`；安装目标从 `command -v nx` 推断，兼容非默认安装路径
