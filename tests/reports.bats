#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_output
}

@test "hunting gera saídas text, JSON e CSV tipadas" {
  run "$TOOL" hunt --quiet --output text,json,csv --output-dir "$TEST_OUTPUT" \
    "$REPO_ROOT/fixtures/hunt.txt"
  [[ "$status" -eq 0 ]]
  [[ -f "$TEST_OUTPUT/hunt.hunt.txt" ]]
  [[ -f "$TEST_OUTPUT/hunt.hunt.csv" ]]
  assert_json_matches "$TEST_OUTPUT/hunt.hunt.json" \
    "$REPO_ROOT/tests/expected/hunt.hunt.json"
}

@test "top limita rankings sem alterar o total processado" {
  run "$TOOL" analyze --quiet --format apache --top 1 --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache.log"
  [[ "$status" -eq 0 ]]
  run jq -e '.summary.parsed_lines == 4 and (.rankings.top_ips | length) == 1' \
    "$TEST_OUTPUT/apache.analysis.json"
  [[ "$status" -eq 0 ]]
}

@test "JSON gerado é sintaticamente válido" {
  run "$TOOL" analyze --quiet --format jsonl --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/events.jsonl"
  [[ "$status" -eq 0 ]]
  run jq -e '.schema_version == "1.0" and .tool.version == "0.2.0"' \
    "$TEST_OUTPUT/events.analysis.json"
  [[ "$status" -eq 0 ]]
}
