#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
release_verifier="$workspace_root/scripts/verify-release-ready.sh"
export IROH_DB_RELEASE_TEST_REAL_JQ
IROH_DB_RELEASE_TEST_REAL_JQ=$(command -v jq)

jq() {
  case "${IROH_DB_RELEASE_TEST_JQ_MODE:-real}" in
    error)
      return 2
      ;;
    safe)
      return 0
      ;;
    real)
      "$IROH_DB_RELEASE_TEST_REAL_JQ" "$@"
      ;;
    *)
      echo "unknown jq test mode: $IROH_DB_RELEASE_TEST_JQ_MODE" >&2
      return 2
      ;;
  esac
}
export -f jq

run_case() {
  local mode=$1
  set +e
  case_output=$(IROH_DB_RELEASE_TEST_JQ_MODE="$mode" bash "$release_verifier" 2>&1)
  case_status=$?
  set -e
}

run_case real
[[ $case_status -eq 1 ]]
[[ $case_output == *"release blocked"* ]]

run_case safe
[[ $case_status -eq 0 ]]
[[ $case_output == *"release dependency sources are registry-safe"* ]]

run_case error
[[ $case_status -ne 0 ]]
[[ $case_output != *"release dependency sources are registry-safe"* ]]

echo "release dependency verifier tests passed"
