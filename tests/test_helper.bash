#!/usr/bin/env bash

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Consumida pelos arquivos .bats após load.
# shellcheck disable=SC2034
TOOL="$REPO_ROOT/redteam_helper.sh"

setup_test_output() {
  TEST_OUTPUT="$BATS_TEST_TMPDIR/artifacts"
  mkdir -p "$TEST_OUTPUT"
}

assert_success() {
  # status/output são variáveis fornecidas pelo Bats após run.
  # shellcheck disable=SC2154
  if [[ "$status" -ne 0 ]]; then
    # shellcheck disable=SC2154
    printf '%s\n' "$output" >&2
    return 1
  fi
}

assert_json_matches() {
  local actual="$1"
  local expected="$2"
  local normalized_actual="$BATS_TEST_TMPDIR/actual.normalized.json"
  local normalized_expected="$BATS_TEST_TMPDIR/expected.normalized.json"

  jq -S 'del(.generated_at) | .input.source = "<fixture>"' \
    "$actual" >"$normalized_actual"
  jq -S . "$expected" >"$normalized_expected"
  run diff -u "$normalized_expected" "$normalized_actual"
  # status/output são variáveis fornecidas pelo Bats após run.
  # shellcheck disable=SC2154
  if [[ "$status" -ne 0 ]]; then
    # shellcheck disable=SC2154
    printf '%s\n' "$output" >&2
  fi
  # shellcheck disable=SC2154
  [[ "$status" -eq 0 ]]
}
