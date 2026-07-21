#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
metadata=$(cargo metadata \
  --manifest-path "$workspace_root/Cargo.toml" \
  --format-version 1 \
  --no-deps)

mapfile -t git_dependencies < <(
  jq -r '.packages[]
    | .name as $package
    | .dependencies[]
    | select(.source != null and (.source | startswith("git+")))
    | "\($package): \(.name) \(.req) from \(.source)"' <<<"$metadata" | sort -u
)

if [[ ${#git_dependencies[@]} -ne 0 ]]; then
  echo "release blocked: Cargo replaces versioned Git dependencies with their registry versions when publishing" >&2
  printf '  %s\n' "${git_dependencies[@]}" >&2
  echo "publish only after these pins are replaced by audited registry releases" >&2
  exit 1
fi

echo "release dependency sources are registry-safe"
