#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/source/lib" "$root/source/tools" "$root/bin"
cp nx.sh install.sh "$root/source/"
cp lib/*.sh "$root/source/lib/"
cp tools/build-bundle.sh "$root/source/tools/"
TARGET_BIN="$root/bin/nx" bash "$root/source/install.sh" --no-run >/dev/null
bash -n "$root/bin/nx"
# Installed command is self contained even if all source modules disappear.
cp "$root/bin/nx" "$root/first"
printf '\n# module-only update\n' >> "$root/source/lib/access.sh"
TARGET_BIN="$root/bin/nx" bash "$root/source/install.sh" --no-run >/dev/null
if cmp -s "$root/first" "$root/bin/nx"; then echo 'module-only update was ignored' >&2; exit 1; fi
rm -rf "$root/source"
bash -c 'source "$1"; declare -F nx_transaction nx_access_sync_files nx_https_transform build_proxy_conf issue_cert >/dev/null' _ "$root/bin/nx"
[[ ! -e "$root/bin/nx.new" ]]
echo 'ok: coherent standalone bundle and custom installation path'
