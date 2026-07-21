#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
metadata=$(cargo metadata \
  --manifest-path "$workspace_root/Cargo.toml" \
  --format-version 1 \
  --no-deps)

if ! git_dependency_lines=$(jq -r '.packages[]
    | .name as $package
    | .dependencies[]
    | select(.source != null and (.source | startswith("git+")))
    | "\($package): \(.name) \(.req) from \(.source)"' <<<"$metadata" | sort -u); then
  echo "release blocked: failed to inspect dependency sources" >&2
  exit 1
fi

git_dependencies=()
if [[ -n $git_dependency_lines ]]; then
  mapfile -t git_dependencies <<<"$git_dependency_lines"
fi

if [[ ${#git_dependencies[@]} -ne 0 ]]; then
  echo "release blocked: Cargo replaces versioned Git dependencies with their registry versions when publishing" >&2
  printf '  %s\n' "${git_dependencies[@]}" >&2
  echo "publish only after these pins are replaced by audited registry releases" >&2
  exit 1
fi

echo "release dependency sources are registry-safe"
