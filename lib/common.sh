#!/usr/bin/env bash

# Utilitários compartilhados de validação, entrada, saída e logging.

# As constantes e variáveis abaixo são consumidas pelos outros módulos sourced.
# shellcheck disable=SC2034
readonly EXIT_USAGE=2
# shellcheck disable=SC2034
readonly EXIT_INPUT=3
# shellcheck disable=SC2034
readonly EXIT_DEPENDENCY=4
# shellcheck disable=SC2034
readonly EXIT_FORMAT=5
# shellcheck disable=SC2034
readonly EXIT_OUTPUT=6

REDTEAM_BASE_DIR="${REDTEAM_BASE_DIR:-}"
QUIET="${QUIET:-0}"
PREPARED_INPUT_FILE=""
# shellcheck disable=SC2034
PREPARED_INPUT_LABEL=""
OUTPUT_TEMP=""
declare -a TEMP_FILES=()
declare -a OUTPUT_FORMATS=()
declare -a GENERATED_REPORTS=()
readonly MAIN_BASHPID="$BASHPID"

info() {
  [[ "$QUIET" == "1" ]] || printf '[INFO] %s\n' "$*" >&2
}

warn() {
  printf '[AVISO] %s\n' "$*" >&2
}

die() {
  local code="$1"
  shift
  printf '[ERRO] %s\n' "$*" >&2
  exit "$code"
}

on_error() {
  local status="$1"
  local line="$2"
  printf '[ERRO] Falha inesperada (código %s) na linha %s.\n' \
    "$status" "$line" >&2
}

register_temp_file() {
  TEMP_FILES+=("$1")
}

cleanup_temp_files() {
  local file

  # Traps EXIT também podem ser herdados por command substitutions. Somente o
  # processo Bash principal é autorizado a remover os temporários registrados.
  ((BASH_SUBSHELL == 0)) || return 0
  [[ "$BASHPID" == "$MAIN_BASHPID" ]] || return 0
  for file in "${TEMP_FILES[@]-}"; do
    if [[ -n "$file" && -f "$file" ]]; then
      rm -f -- "$file"
    fi
  done
}

new_temp_file() {
  mktemp "${TMPDIR:-/tmp}/redteam-helper.XXXXXX"
}

require_option_value() {
  local option="$1"
  local value="$2"
  [[ -n "$value" ]] || die "$EXIT_USAGE" "A opção $option requer um valor."
}

require_commands() {
  local command
  local -a missing=()

  for command in "$@"; do
    command -v "$command" >/dev/null 2>&1 || missing+=("$command")
  done

  if ((${#missing[@]} > 0)); then
    die "$EXIT_DEPENDENCY" \
      "Dependências ausentes: ${missing[*]}. Consulte a seção Instalação do README."
  fi
}

validate_positive_integer() {
  local value="$1"
  local option="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$EXIT_USAGE" \
    "$option deve ser um inteiro positivo."
}

validate_format() {
  case "$1" in
    auto|apache|jsonl|syslog) ;;
    *) die "$EXIT_USAGE" "Formato inválido: $1 (use auto, apache, jsonl ou syslog)." ;;
  esac
}

parse_output_formats() {
  local raw="$1"
  local item
  local normalized=","
  local -a requested=()

  IFS=',' read -r -a requested <<<"$raw"
  OUTPUT_FORMATS=()
  ((${#requested[@]} > 0)) || die "$EXIT_USAGE" "Informe ao menos um formato de saída."

  for item in "${requested[@]}"; do
    case "$item" in
      text|json|csv) ;;
      *) die "$EXIT_USAGE" "Formato de saída inválido: ${item:-vazio}." ;;
    esac
    if [[ "$normalized" != *",$item,"* ]]; then
      OUTPUT_FORMATS+=("$item")
      normalized+="$item,"
    fi
  done
}

resolve_path() {
  local input="$1"
  local candidate

  [[ -n "$input" ]] || die "$EXIT_INPUT" "Caminho vazio."
  if [[ "$input" = /* || "$input" =~ ^[A-Za-z]:[/\\] || -e "$input" ]]; then
    printf '%s\n' "$input"
    return 0
  fi

  if [[ -n "$REDTEAM_BASE_DIR" ]]; then
    candidate="${REDTEAM_BASE_DIR%/}/$input"
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  printf '%s\n' "$input"
}

prepare_input() {
  local input_request="$1"

  if [[ "$input_request" == "-" ]]; then
    PREPARED_INPUT_FILE="$(new_temp_file)" || die "$EXIT_INPUT" \
      "Não foi possível criar arquivo temporário para stdin."
    register_temp_file "$PREPARED_INPUT_FILE"
    cat >"$PREPARED_INPUT_FILE"
    PREPARED_INPUT_LABEL="stdin"
  else
    PREPARED_INPUT_FILE="$(resolve_path "$input_request")"
    PREPARED_INPUT_LABEL="$input_request"
  fi

  [[ -f "$PREPARED_INPUT_FILE" ]] || die "$EXIT_INPUT" \
    "Arquivo não encontrado ou não regular: $PREPARED_INPUT_FILE"
  [[ -r "$PREPARED_INPUT_FILE" ]] || die "$EXIT_INPUT" \
    "Sem permissão de leitura: $PREPARED_INPUT_FILE"
  [[ -s "$PREPARED_INPUT_FILE" ]] || die "$EXIT_INPUT" "O arquivo de entrada está vazio."
}

sanitize_stem() {
  local label="$1"
  local stem

  stem="$(basename "$label")"
  stem="${stem%.*}"
  stem="$(printf '%s' "$stem" | sed 's/[^A-Za-z0-9._-]/_/g')"
  [[ -n "$stem" ]] || stem="report"
  printf '%s\n' "$stem"
}

current_timestamp() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

prepare_output_directory() {
  local directory="$1"

  if [[ -e "$directory" && ! -d "$directory" ]]; then
    die "$EXIT_OUTPUT" "O destino existe e não é diretório: $directory"
  fi
  mkdir -p -- "$directory" || die "$EXIT_OUTPUT" \
    "Não foi possível criar o diretório de saída: $directory"
  [[ -w "$directory" ]] || die "$EXIT_OUTPUT" \
    "Sem permissão de escrita no diretório: $directory"
}

assert_output_available() {
  local destination="$1"
  local force="$2"

  if [[ -e "$destination" && "$force" != "1" ]]; then
    die "$EXIT_OUTPUT" "Artefato já existe: $destination (use --force para substituir)."
  fi
}

create_output_temp() {
  local destination="$1"
  local directory
  local name

  directory="$(dirname "$destination")"
  name="$(basename "$destination")"
  OUTPUT_TEMP="$(mktemp "$directory/.${name}.tmp.XXXXXX")" || die "$EXIT_OUTPUT" \
    "Não foi possível criar saída temporária em $directory."
  register_temp_file "$OUTPUT_TEMP"
}

publish_output() {
  local temporary="$1"
  local destination="$2"

  mv -f -- "$temporary" "$destination" || die "$EXIT_OUTPUT" \
    "Não foi possível publicar o artefato: $destination"
  GENERATED_REPORTS+=("$destination")
}

run_grep_allow_no_match() {
  local status

  if grep "$@"; then
    return 0
  else
    status=$?
  fi

  [[ "$status" == "1" ]] && return 0
  die "$EXIT_INPUT" "Falha durante a pesquisa com grep (código $status)."
}
