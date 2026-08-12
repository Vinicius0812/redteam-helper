#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_output
}

@test "help e versão funcionam sem executar análise" {
  run "$TOOL" --version
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"0.2.0"* ]]

  run "$TOOL" --help
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"triagem defensiva"* ]]
}

@test "comportamento privilegiado de manutenção não existe" {
  run "$TOOL" --maintain
  [[ "$status" -eq 2 ]]
  [[ "$output" != *"apt dist-upgrade"* ]]
}

@test "formato desconhecido exige seleção explícita" {
  run "$TOOL" analyze --quiet --output-dir "$TEST_OUTPUT" \
    "$REPO_ROOT/fixtures/unknown.log"
  [[ "$status" -eq 5 ]]
  [[ "$output" == *"Não foi possível detectar"* ]]
}

@test "relatório existente não é sobrescrito sem force" {
  run "$TOOL" analyze --quiet --format apache --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache.log"
  [[ "$status" -eq 0 ]]

  run "$TOOL" analyze --quiet --format apache --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache.log"
  [[ "$status" -eq 6 ]]
  [[ "$output" == *"já existe"* ]]

  run "$TOOL" analyze --quiet --force --format apache --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache.log"
  [[ "$status" -eq 0 ]]
}

@test "regex trata padrão iniciado por hífen como dado" {
  run "$TOOL" regex --fixed -- -needle "$REPO_ROOT/fixtures/regex.txt"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"-needle indicador"* ]]
}

@test "regex suporta busca recursiva, glob e ignore-case" {
  run "$TOOL" regex --ignore-case --include '*.txt' 'flag{' "$REPO_ROOT/fixtures"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"FLAG{CASE_INSENSITIVE}"* ]]
}

@test "entrada original permanece inalterada" {
  local before
  local after
  before="$(cksum "$REPO_ROOT/fixtures/apache.log")"

  run "$TOOL" analyze --quiet --format apache --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache.log"
  [[ "$status" -eq 0 ]]
  after="$(cksum "$REPO_ROOT/fixtures/apache.log")"
  [[ "$before" == "$after" ]]
}

@test "stdin pode ser usado como entrada" {
  run bash -c '"$1" analyze --quiet --format apache --input - --output json --output-dir "$2" <"$3"' \
    _ "$TOOL" "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache.log"
  [[ "$status" -eq 0 ]]
  [[ -f "$TEST_OUTPUT/stdin.analysis.json" ]]
  run jq -e '.summary.parsed_lines == 4' "$TEST_OUTPUT/stdin.analysis.json"
  [[ "$status" -eq 0 ]]
}

@test "aliases legados continuam funcionais" {
  run "$TOOL" --analyze --quiet --format apache --output json \
    --output-dir "$TEST_OUTPUT" "$REPO_ROOT/fixtures/apache.log"
  [[ "$status" -eq 0 ]]
  [[ -f "$TEST_OUTPUT/apache.analysis.json" ]]
}

@test "REDTEAM_BASE_DIR resolve uma entrada relativa ausente no cwd" {
  run env REDTEAM_BASE_DIR="$REPO_ROOT/fixtures" \
    "$TOOL" analyze --quiet --format apache --output json \
    --output-dir "$TEST_OUTPUT" apache.log
  [[ "$status" -eq 0 ]]
  [[ -f "$TEST_OUTPUT/apache.analysis.json" ]]
}
