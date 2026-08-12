#!/usr/bin/env bash

set -Eeuo pipefail

CHECK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CHECK_DIR
REPO_ROOT="$(cd "$CHECK_DIR/.." && pwd)"
readonly REPO_ROOT
cd "$REPO_ROOT"

CHECK_TMP_DIR=""
cleanup_check_tmp() {
  if [[ -n "$CHECK_TMP_DIR" && "$CHECK_TMP_DIR" == "$REPO_ROOT"/.check-tmp.* \
    && -d "$CHECK_TMP_DIR" ]]; then
    rm -rf -- "$CHECK_TMP_DIR"
  fi
}
trap cleanup_check_tmp EXIT

CHECK_TMP_DIR="$(mktemp -d "$REPO_ROOT/.check-tmp.XXXXXX")"
export BATS_TMPDIR="$CHECK_TMP_DIR"

if [[ -x "$REPO_ROOT/.tools/jq" || -x "$REPO_ROOT/.tools/jq.exe" ]]; then
  export PATH="$REPO_ROOT/.tools:$PATH"
fi
for bats_bin in "$REPO_ROOT"/.tools/bats-core-*/bin; do
  if [[ -d "$bats_bin" ]]; then
    export PATH="$bats_bin:$PATH"
    break
  fi
done

missing=()
for command in bats jq shellcheck; do
  command -v "$command" >/dev/null 2>&1 || missing+=("$command")
done
if ((${#missing[@]} > 0)); then
  printf '[ERRO] Ferramentas de desenvolvimento ausentes: %s\n' "${missing[*]}" >&2
  printf 'Consulte a seção Desenvolvimento do README.md.\n' >&2
  exit 4
fi

printf '[CHECK] Sintaxe Bash\n'
bash -n redteam_helper.sh lib/*.sh scripts/*.sh tests/test_helper.bash

printf '[CHECK] Consistência da versão\n'
file_version="$(<VERSION)"
cli_version="$(./redteam_helper.sh --version)"
if [[ "$cli_version" != "redteam_helper.sh $file_version" ]]; then
  printf '[ERRO] VERSION (%s) diverge da CLI (%s).\n' \
    "$file_version" "$cli_version" >&2
  exit 1
fi

printf '[CHECK] ShellCheck\n'
shellcheck -x redteam_helper.sh lib/*.sh scripts/*.sh tests/test_helper.bash

printf '[CHECK] Testes Bats\n'
bats tests

printf '[OK] Todas as verificações passaram.\n'
