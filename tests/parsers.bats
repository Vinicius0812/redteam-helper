#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_output
}

@test "Apache Common/Combined é detectado e exportado" {
  run "$TOOL" analyze --quiet --output text,json,csv --output-dir "$TEST_OUTPUT" \
    "$REPO_ROOT/fixtures/apache.log"
  assert_success
  [[ -f "$TEST_OUTPUT/apache.analysis.txt" ]]
  [[ -f "$TEST_OUTPUT/apache.analysis.csv" ]]
  assert_json_matches "$TEST_OUTPUT/apache.analysis.json" \
    "$REPO_ROOT/tests/expected/apache.analysis.json"
  run awk -F, 'NR > 1 {count++} END {exit count == 4 ? 0 : 1}' \
    "$TEST_OUTPUT/apache.analysis.csv"
  [[ "$status" -eq 0 ]]
}

@test "JSON Lines suporta aliases simples e campos ECS aninhados" {
  run "$TOOL" analyze --quiet --output json --output-dir "$TEST_OUTPUT" \
    "$REPO_ROOT/fixtures/events.jsonl"
  [[ "$status" -eq 0 ]]
  assert_json_matches "$TEST_OUTPUT/events.analysis.json" \
    "$REPO_ROOT/tests/expected/events.analysis.json"
}

@test "syslog RFC3164 é normalizado" {
  run "$TOOL" analyze --quiet --output json --output-dir "$TEST_OUTPUT" \
    "$REPO_ROOT/fixtures/syslog-rfc3164.log"
  [[ "$status" -eq 0 ]]
  assert_json_matches "$TEST_OUTPUT/syslog-rfc3164.analysis.json" \
    "$REPO_ROOT/tests/expected/syslog-rfc3164.analysis.json"
}

@test "syslog RFC5424 é normalizado" {
  run "$TOOL" analyze --quiet --output json --output-dir "$TEST_OUTPUT" \
    "$REPO_ROOT/fixtures/syslog-rfc5424.log"
  [[ "$status" -eq 0 ]]
  assert_json_matches "$TEST_OUTPUT/syslog-rfc5424.analysis.json" \
    "$REPO_ROOT/tests/expected/syslog-rfc5424.analysis.json"
}

@test "linhas malformadas são contabilizadas sem interromper o lote" {
  run "$TOOL" analyze --quiet --format apache --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache-malformed.log"
  [[ "$status" -eq 0 ]]
  run jq -e '.summary.parsed_lines == 1 and .summary.invalid_lines == 4' \
    "$TEST_OUTPUT/apache-malformed.analysis.json"
  [[ "$status" -eq 0 ]]
}
