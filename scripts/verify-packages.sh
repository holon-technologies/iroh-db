#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/iroh-db-package-verify.XXXXXX")
trap 'rm -rf -- "$temporary_root"' EXIT

metadata=$(cargo metadata \
  --manifest-path "$workspace_root/Cargo.toml" \
  --format-version 1 \
  --no-deps)
mapfile -t package_specs < <(
  jq -r '(.workspace_members[]) as $member
    | .packages[]
    | select(.id == $member)
    | [.name, .version]
    | @tsv' <<<"$metadata" | sort
)

if [[ ${#package_specs[@]} -eq 0 ]]; then
  echo "no workspace packages found" >&2
  exit 1
fi

cargo package \
  --manifest-path "$workspace_root/Cargo.toml" \
  --workspace \
  --no-verify \
  --allow-dirty \
  --target-dir "$temporary_root/target"

mkdir -p "$temporary_root/unpacked"
declare -A package_directories=()
for package_spec in "${package_specs[@]}"; do
  IFS=$'\t' read -r package_name package_version <<<"$package_spec"
  archive="$temporary_root/target/package/$package_name-$package_version.crate"
  if [[ ! -f "$archive" ]]; then
    echo "missing package archive: $archive" >&2
    exit 1
  fi
  tar -xzf "$archive" -C "$temporary_root/unpacked"
  package_directory="$temporary_root/unpacked/$package_name-$package_version"
  if [[ ! -f "$package_directory/Cargo.toml" ]]; then
    echo "package archive has no normalized Cargo.toml: $archive" >&2
    exit 1
  fi
  package_directories["$package_name"]=$package_directory
done

patch_arguments=()
for package_spec in "${package_specs[@]}"; do
  IFS=$'\t' read -r package_name _ <<<"$package_spec"
  patch_arguments+=(
    --config
    "patch.crates-io.$package_name.path='${package_directories[$package_name]}'"
  )
done

for package_spec in "${package_specs[@]}"; do
  IFS=$'\t' read -r package_name _ <<<"$package_spec"
  echo "verifying packaged crate $package_name"
  cargo check \
    --manifest-path "${package_directories[$package_name]}/Cargo.toml" \
    --all-targets \
    --target-dir "$temporary_root/build" \
    "${patch_arguments[@]}"
done
