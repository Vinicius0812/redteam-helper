#!/usr/bin/env bash

# RedTeam Helper - triagem defensiva e reprodutível de logs.
# Use somente em dados e ambientes próprios ou explicitamente autorizados.

set -Eeuo pipefail

readonly VERSION="0.2.0"
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/parsers.sh
source "$SCRIPT_DIR/lib/parsers.sh"
# shellcheck source=lib/reports.sh
source "$SCRIPT_DIR/lib/reports.sh"

trap cleanup_temp_files EXIT
trap 'on_error "$?" "$LINENO"' ERR

usage() {
  cat <<EOF
RedTeam Helper $VERSION - triagem defensiva de logs para labs autorizados.

Uso:
  $SCRIPT_NAME analyze [opções] <arquivo|->
  $SCRIPT_NAME hunt [opções] <arquivo|->
  $SCRIPT_NAME regex [opções] <padrão> <arquivo|diretório>
  $SCRIPT_NAME menu
  $SCRIPT_NAME --version
  $SCRIPT_NAME --help

Comandos:
  analyze   Normaliza Apache, JSON Lines ou syslog e gera relatórios.
  hunt      Extrai candidatos a flags, hashes, URLs, IPs e domínios.
  regex     Pesquisa defensiva somente leitura em arquivo ou diretório.
  menu      Abre o menu interativo, sem operações privilegiadas.

Compatibilidade:
  --analyze, --hunt e --regex continuam aceitos como aliases.

Execute '$SCRIPT_NAME <comando> --help' para ver as opções do comando.
EOF
}

analyze_usage() {
  cat <<EOF
Uso: $SCRIPT_NAME analyze [opções] <arquivo|->

Opções:
  --input <arquivo|->       Entrada; '-' lê de stdin.
  --format <formato>        auto, apache, jsonl ou syslog (padrão: auto).
  --output-dir <diretório> Destino dos artefatos (padrão: ./artifacts).
  --output <lista>          text,json,csv separados por vírgula
                            (padrão: text,json).
  --top <n>                 Limite por ranking (padrão: 10).
  --force                   Substitui artefatos existentes atomicamente.
  --quiet                   Omite mensagens informativas no stderr.
  -h, --help                Mostra esta ajuda.

Exemplos:
  $SCRIPT_NAME analyze fixtures/apache.log
  $SCRIPT_NAME analyze --format jsonl --output json,csv events.jsonl
  cat access.log | $SCRIPT_NAME analyze --format apache --input -
EOF
}

hunt_usage() {
  cat <<EOF
Uso: $SCRIPT_NAME hunt [opções] <arquivo|->

Opções:
  --input <arquivo|->       Entrada; '-' lê de stdin.
  --output-dir <diretório> Destino dos artefatos (padrão: ./artifacts).
  --output <lista>          text,json,csv separados por vírgula
                            (padrão: text,json).
  --top <n>                 Limite por tipo de indicador (padrão: 20).
  --force                   Substitui artefatos existentes atomicamente.
  --quiet                   Omite mensagens informativas no stderr.
  -h, --help                Mostra esta ajuda.
EOF
}

regex_usage() {
  cat <<EOF
Uso: $SCRIPT_NAME regex [opções] <padrão> <arquivo|diretório>

Opções:
  --fixed                   Interpreta o padrão como texto literal.
  --ignore-case             Ignora diferenças entre maiúsculas e minúsculas.
  --include <glob>          Glob de arquivos em busca recursiva (padrão: *).
  -h, --help                Mostra esta ajuda.

O padrão é passado ao grep com '-e' e o alvo depois de '--', evitando que
valores iniciados por '-' sejam interpretados como opções.
EOF
}

analyze_command() {
  local input=""
  local format="auto"
  local output_dir="$PWD/artifacts"
  local outputs="text,json"
  local top="10"
  local force="0"

  while (($# > 0)); do
    case "$1" in
      --input)
        require_option_value "$1" "${2-}"
        input="$2"
        shift 2
        ;;
      --format)
        require_option_value "$1" "${2-}"
        format="$2"
        shift 2
        ;;
      --output-dir)
        require_option_value "$1" "${2-}"
        output_dir="$2"
        shift 2
        ;;
      --output)
        require_option_value "$1" "${2-}"
        outputs="$2"
        shift 2
        ;;
      --top)
        require_option_value "$1" "${2-}"
        top="$2"
        shift 2
        ;;
      --force)
        force="1"
        shift
        ;;
      --quiet)
        QUIET="1"
        shift
        ;;
      -h|--help)
        analyze_usage
        return 0
        ;;
      --)
        shift
        while (($# > 0)); do
          [[ -z "$input" ]] || die "$EXIT_USAGE" "Mais de uma entrada foi informada."
          input="$1"
          shift
        done
        ;;
      -*)
        die "$EXIT_USAGE" "Opção desconhecida em analyze: $1"
        ;;
      *)
        [[ -z "$input" ]] || die "$EXIT_USAGE" "Mais de uma entrada foi informada."
        input="$1"
        shift
        ;;
    esac
  done

  [[ -n "$input" ]] || die "$EXIT_USAGE" "Informe um arquivo ou '-' para stdin."
  validate_format "$format"
  validate_positive_integer "$top" "--top"
  parse_output_formats "$outputs"
  require_commands awk basename cat cp date dirname grep jq mkdir mktemp mv rm sed sort uniq
  prepare_input "$input"

  if [[ "$format" == "auto" ]]; then
    format="$(detect_log_format "$PREPARED_INPUT_FILE")"
    [[ "$format" != "unknown" ]] || die "$EXIT_FORMAT" \
      "Não foi possível detectar o formato. Use --format apache|jsonl|syslog."
  fi

  info "Formato selecionado: $format"
  analyze_logs "$PREPARED_INPUT_FILE" "$PREPARED_INPUT_LABEL" "$format" \
    "$output_dir" "$top" "$force"
}

hunt_command() {
  local input=""
  local output_dir="$PWD/artifacts"
  local outputs="text,json"
  local top="20"
  local force="0"

  while (($# > 0)); do
    case "$1" in
      --input)
        require_option_value "$1" "${2-}"
        input="$2"
        shift 2
        ;;
      --output-dir)
        require_option_value "$1" "${2-}"
        output_dir="$2"
        shift 2
        ;;
      --output)
        require_option_value "$1" "${2-}"
        outputs="$2"
        shift 2
        ;;
      --top)
        require_option_value "$1" "${2-}"
        top="$2"
        shift 2
        ;;
      --force)
        force="1"
        shift
        ;;
      --quiet)
        QUIET="1"
        shift
        ;;
      -h|--help)
        hunt_usage
        return 0
        ;;
      --)
        shift
        while (($# > 0)); do
          [[ -z "$input" ]] || die "$EXIT_USAGE" "Mais de uma entrada foi informada."
          input="$1"
          shift
        done
        ;;
      -*)
        die "$EXIT_USAGE" "Opção desconhecida em hunt: $1"
        ;;
      *)
        [[ -z "$input" ]] || die "$EXIT_USAGE" "Mais de uma entrada foi informada."
        input="$1"
        shift
        ;;
    esac
  done

  [[ -n "$input" ]] || die "$EXIT_USAGE" "Informe um arquivo ou '-' para stdin."
  validate_positive_integer "$top" "--top"
  parse_output_formats "$outputs"
  require_commands awk basename cat cp date dirname grep jq mkdir mktemp mv rm sed sort uniq
  prepare_input "$input"
  hunt_file "$PREPARED_INPUT_FILE" "$PREPARED_INPUT_LABEL" "$output_dir" \
    "$top" "$force"
}

regex_command() {
  local fixed="0"
  local ignore_case="0"
  local include="*"
  local pattern=""
  local target=""
  local -a grep_args=(-n -I)

  while (($# > 0)); do
    case "$1" in
      --fixed)
        fixed="1"
        shift
        ;;
      --ignore-case)
        ignore_case="1"
        shift
        ;;
      --include)
        require_option_value "$1" "${2-}"
        include="$2"
        shift 2
        ;;
      -h|--help)
        regex_usage
        return 0
        ;;
      --)
        shift
        break
        ;;
      -*)
        # Um padrão iniciado por '-' é aceito quando resta também o alvo.
        if [[ -z "$pattern" && $# -ge 2 ]]; then
          pattern="$1"
          shift
        else
          die "$EXIT_USAGE" "Opção desconhecida em regex: $1"
        fi
        ;;
      *)
        if [[ -z "$pattern" ]]; then
          pattern="$1"
        elif [[ -z "$target" ]]; then
          target="$1"
        else
          die "$EXIT_USAGE" "Argumentos excedentes em regex."
        fi
        shift
        ;;
    esac
  done

  while (($# > 0)); do
    if [[ -z "$pattern" ]]; then
      pattern="$1"
    elif [[ -z "$target" ]]; then
      target="$1"
    else
      die "$EXIT_USAGE" "Argumentos excedentes em regex."
    fi
    shift
  done

  [[ -n "$pattern" ]] || die "$EXIT_USAGE" "O padrão não pode ser vazio."
  [[ -n "$target" ]] || die "$EXIT_USAGE" "Informe um arquivo ou diretório."
  require_commands grep
  target="$(resolve_path "$target")"
  [[ -e "$target" ]] || die "$EXIT_INPUT" "Caminho não encontrado: $target"

  if [[ "$fixed" == "1" ]]; then
    grep_args+=(-F)
  else
    grep_args+=(-E)
  fi
  [[ "$ignore_case" == "1" ]] && grep_args+=(-i)

  if [[ -f "$target" ]]; then
    run_grep_allow_no_match "${grep_args[@]}" -e "$pattern" -- "$target"
  elif [[ -d "$target" ]]; then
    run_grep_allow_no_match "${grep_args[@]}" -R --include="$include" \
      -e "$pattern" -- "$target"
  else
    die "$EXIT_INPUT" "O alvo deve ser arquivo regular ou diretório: $target"
  fi
}

print_menu() {
  cat <<'EOF'
============================================
 RedTeam Helper 0.2.0 - triagem defensiva
============================================
1) Analisar log
2) Hunt de indicadores/flags
3) Pesquisar com regex
4) Ajuda
5) Sair
EOF
}

interactive_menu() {
  local option input format pattern target

  [[ -t 0 ]] || die "$EXIT_USAGE" "O menu requer um terminal interativo."
  while true; do
    print_menu
    read -r -p "Escolha [1-5]: " option
    case "${option:-}" in
      1)
        read -r -p "Arquivo de log: " input
        read -r -p "Formato [auto/apache/jsonl/syslog] (auto): " format
        analyze_command --format "${format:-auto}" "$input"
        ;;
      2)
        read -r -p "Arquivo para hunting: " input
        hunt_command "$input"
        ;;
      3)
        read -r -p "Regex: " pattern
        read -r -p "Arquivo ou diretório: " target
        regex_command "$pattern" "$target"
        ;;
      4)
        usage
        ;;
      5)
        return 0
        ;;
      *)
        warn "Opção inválida."
        ;;
    esac
    printf '\n'
  done
}

main() {
  if (($# == 0)); then
    usage
    return 0
  fi

  case "$1" in
    analyze|--analyze)
      shift
      analyze_command "$@"
      ;;
    hunt|--hunt)
      shift
      hunt_command "$@"
      ;;
    regex|--regex)
      shift
      regex_command "$@"
      ;;
    menu)
      shift
      (($# == 0)) || die "$EXIT_USAGE" "O comando menu não recebe argumentos."
      interactive_menu
      ;;
    --version|-V)
      printf '%s %s\n' "$SCRIPT_NAME" "$VERSION"
      ;;
    --help|-h|help)
      usage
      ;;
    *)
      die "$EXIT_USAGE" "Comando desconhecido: $1 (use --help)"
      ;;
  esac
}

main "$@"
