#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:?output file required}"
# Replace the eager loader with module contents, preserving execution guard.
awk '/^# All modules load before/ { exit } { print }' "$root/nx.sh" > "$out"
for module in templates certificates transactions access https; do
  cat "$root/lib/$module.sh" >> "$out"
  printf '\n' >> "$out"
done
cat >> "$out" <<'GUARD'
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main
fi
GUARD
bash -n "$out"
