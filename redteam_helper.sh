#!/usr/bin/env bash

# redteam_helper.sh
# Helper para CTF de analise de logs e manipulacao de arquivos no Kali.

set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
# Diretorio base opcional para resolver caminhos relativos.
# Exemplo: export REDTEAM_BASE_DIR="/home/vinicius/logs"
REDTEAM_BASE_DIR="${REDTEAM_BASE_DIR:-}"

trap 'echo "[ERRO] Falha na linha $LINENO. Comando: $BASH_COMMAND" >&2' ERR

usage() {
  cat <<EOF
Red Team Helper v2 - utilitario para CTF de logs e triagem rapida.

Uso rapido:
  $SCRIPT_NAME                      Modo menu interativo
  $SCRIPT_NAME --help               Mostra esta ajuda

Funcoes:
  --maintain                        Executa manutencao do Kali:
                                    sudo apt update && sudo apt dist-upgrade -y
  --analyze <arquivo_log>           Analisa log (apache/json/syslog) e extrai:
                                    top IP, top URL, top User-Agent, status, metodo e pico/min.
                                    Gera relatorio .txt e .json.
  --hunt <arquivo_log>              Faz IOC/Flag hunting no arquivo:
                                    flags, hashes, URLs, IPs e dominios.
                                    Gera relatorio .txt.
  --regex "<padrao>" <alvo_txt>     Filtra conteudo com grep -E em arquivo .txt
                                    ou diretorio (recursivo).

Variaveis de ambiente:
  REDTEAM_BASE_DIR   Diretorio base para caminhos relativos de logs/arquivos.
                     Ex.: /home/vinicius/logs

Exemplos:
  $SCRIPT_NAME --analyze /home/vinicius/logs/logs.txt
  $SCRIPT_NAME --analyze logs.txt
  $SCRIPT_NAME --hunt /home/vinicius/logs/logs.txt
  $SCRIPT_NAME --regex "flag\\{.*\\}" /home/vinicius/logs
EOF
}

info() { echo "[INFO] $*"; }
warn() { echo "[AVISO] $*"; }
die() { echo "[ERRO] $*" >&2; exit 1; }

resolve_path() {
  local input="$1"
  local candidate

  [[ -n "$input" ]] || die "Caminho vazio."

  # Se for absoluto ou ja existir no cwd, usa direto.
  if [[ "$input" = /* || -e "$input" ]]; then
    echo "$input"
    return
  fi

  # Base definida pelo usuario.
  if [[ -n "$REDTEAM_BASE_DIR" ]]; then
    candidate="${REDTEAM_BASE_DIR%/}/$input"
    if [[ -e "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  fi

  # Fallback: retorna o que veio (erro detalhado sera tratado adiante).
  echo "$input"
}

require_cmds() {
  local missing=()
  local cmd
  for cmd in awk grep sort uniq sed date mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if ((${#missing[@]} > 0)); then
    die "Dependencias ausentes: ${missing[*]}"
  fi
}

run_maintenance() {
  info "Executando: sudo apt update && sudo apt dist-upgrade -y"
  sudo apt update
  sudo apt dist-upgrade -y
  info "Manutencao concluida."
}

detect_log_format() {
  local file="$1"
  local first
  first="$(grep -m1 -v '^[[:space:]]*$' "$file" || true)"

  if [[ -z "$first" ]]; then
    echo "unknown"
    return
  fi

  if [[ "$first" =~ ^\{.*\}$ ]]; then
    echo "json"
  elif printf '%s\n' "$first" | grep -Eq '^[A-Z][a-z]{2}[[:space:]][[:digit:]]{1,2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}'; then
    echo "syslog"
  else
    echo "apache"
  fi
}

normalize_apache() {
  local file="$1"
  awk '
  {
    ip=$1
    method="-"; url="-"; status="-"; ua="-"; minute="-"

    req="-"
    if (match($0, /"[^"]*"/)) {
      req=substr($0, RSTART+1, RLENGTH-2)
      split(req, rq, " ")
      if (length(rq) >= 2) {
        method=rq[1]
        url=rq[2]
      }
    }

    # status no Combined: apos request e referer.
    n=split($0, q, "\"")
    if (n >= 3) {
      rest=q[3]
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", rest)
      split(rest, t, /[[:space:]]+/)
      if (t[1] ~ /^[0-9]{3}$/) status=t[1]
    }
    if (n >= 6) ua=q[n-1]

    # timestamp [10/Oct/2000:13:55:36 -0700] -> 10/Oct/2000:13:55
    if (match($0, /\[[^]]+\]/)) {
      ts=substr($0, RSTART+1, RLENGTH-2)
      split(ts, p, " ")
      if (length(p[1]) >= 17) minute=substr(p[1], 1, 17)
    }

    if (ip == "") ip="-"
    if (url == "") url="-"
    if (ua == "") ua="-"
    if (status == "") status="-"
    if (method == "") method="-"
    if (minute == "") minute="-"

    print ip "\t" url "\t" ua "\t" status "\t" method "\t" minute
  }' "$file"
}

normalize_json() {
  local file="$1"
  awk '
  function jstr(line, key,   p,s) {
    p="\"" key "\"[[:space:]]*:[[:space:]]*\"[^\"]*\""
    if (match(line, p)) {
      s=substr(line, RSTART, RLENGTH)
      sub(/^"[^"]*"[[:space:]]*:[[:space:]]*"/, "", s)
      sub(/"$/, "", s)
      return s
    }
    return "-"
  }
  function jnum(line, key,   p,s) {
    p="\"" key "\"[[:space:]]*:[[:space:]]*[0-9]{3}"
    if (match(line, p)) {
      s=substr(line, RSTART, RLENGTH)
      sub(/^"[^"]*"[[:space:]]*:[[:space:]]*/, "", s)
      return s
    }
    return "-"
  }
  function minute(ts) {
    if (ts == "-" || length(ts) < 16) return "-"
    return substr(ts, 1, 16)
  }
  {
    ip=jstr($0, "ip")
    if (ip == "-") ip=jstr($0, "client_ip")

    url=jstr($0, "url")
    if (url == "-") url=jstr($0, "path")
    if (url == "-") url=jstr($0, "uri")

    ua=jstr($0, "user_agent")
    if (ua == "-") ua=jstr($0, "ua")

    method=jstr($0, "method")
    status=jnum($0, "status")
    ts=jstr($0, "timestamp")
    if (ts == "-") ts=jstr($0, "time")

    print ip "\t" url "\t" ua "\t" status "\t" method "\t" minute(ts)
  }' "$file"
}

normalize_syslog() {
  local file="$1"
  awk '
  {
    ip="-"; url="-"; ua="-"; status="-"; method="-"; minute="-"

    if (match($0, /([0-9]{1,3}\.){3}[0-9]{1,3}/)) ip=substr($0, RSTART, RLENGTH)
    if (match($0, /(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH)/)) method=substr($0, RSTART, RLENGTH)
    if (match($0, /\/[A-Za-z0-9._~:\/?#\[\]@!$&()*+,;=%-]*/)) url=substr($0, RSTART, RLENGTH)
    if (match($0, /[[:space:]][1-5][0-9][0-9][[:space:]]/)) {
      status=substr($0, RSTART+1, RLENGTH-2)
    }
    if (match($0, /"[^"]*"$/)) {
      ua=substr($0, RSTART+1, RLENGTH-2)
    }

    # Exemplo syslog: Mar 24 15:02:31 ...
    if (match($0, /^[A-Z][a-z]{2}[[:space:]][ 0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}/)) {
      minute=substr($0, RSTART, RLENGTH)
      gsub(/[[:space:]]+/, " ", minute)
    }

    print ip "\t" url "\t" ua "\t" status "\t" method "\t" minute
  }' "$file"
}

normalize_log_to_tsv() {
  local file="$1"
  local format="$2"
  local out="$3"

  case "$format" in
    apache) normalize_apache "$file" >"$out" ;;
    json) normalize_json "$file" >"$out" ;;
    syslog) normalize_syslog "$file" >"$out" ;;
    *) die "Formato de log nao suportado: $format" ;;
  esac
}

top_count_from_col() {
  local tsv="$1"
  local col="$2"
  local desc="$3"

  # awk seleciona coluna; sort/uniq calculam frequencia.
  local result
  result="$(awk -F'\t' -v c="$col" '($c != "-" && $c != "") {print $c}' "$tsv" | sort | uniq -c | sort -nr | head -n1 || true)"
  if [[ -n "$result" ]]; then
    echo "$desc: $result"
  else
    echo "$desc: sem dados"
  fi
}

find_suspicious_endpoints() {
  local tsv="$1"
  awk -F'\t' '
    $2 ~ /(\/login|\/wp-login|\/xmlrpc|\/admin|phpmyadmin|\.env)/ {print $2}
  ' "$tsv" | sort | uniq -c | sort -nr | head -n5
}

build_hunt_report() {
  local file="$1"

  echo "### IOC/Flag Hunt"
  echo "Arquivo: $file"
  echo
  echo "[flags]"
  grep -Eoi '(flag|ctf)\{[^}]+\}' "$file" | sort | uniq -c | sort -nr || true
  echo
  echo "[hashes]"
  grep -Eo '\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b' "$file" | sort | uniq -c | sort -nr || true
  echo
  echo "[urls]"
  grep -Eo 'https?://[^"[:space:]]+' "$file" | sed 's/[",;]$//' | sort | uniq -c | sort -nr | head -n20 || true
  echo
  echo "[ips]"
  grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$file" | sort | uniq -c | sort -nr | head -n20 || true
  echo
  echo "[domains]"
  grep -Eo '\b([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b' "$file" | sort | uniq -c | sort -nr | head -n20 || true
}

json_escape() {
  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

analyze_logs() {
  local file
  file="$(resolve_path "$1")"
  [[ -f "$file" ]] || die "Arquivo nao encontrado: $file"
  [[ -r "$file" ]] || die "Sem permissao de leitura: $file"

  local format tsv report_txt report_json dir base ts
  format="$(detect_log_format "$file")"
  [[ "$format" != "unknown" ]] || die "Arquivo vazio ou sem linhas validas."
  info "Formato detectado: $format"

  tsv="$(mktemp)"
  normalize_log_to_tsv "$file" "$format" "$tsv"

  dir="$(dirname "$file")"
  base="$(basename "$file")"
  ts="$(date +%Y%m%d_%H%M%S)"
  report_txt="${dir}/${base}.report_${ts}.txt"
  report_json="${dir}/${base}.report_${ts}.json"

  {
    echo "### Log Analysis Report"
    echo "Arquivo: $file"
    echo "Formato detectado: $format"
    echo "Gerado em: $(date -Is)"
    echo
    top_count_from_col "$tsv" 1 "Top IP"
    top_count_from_col "$tsv" 2 "Top URL"
    top_count_from_col "$tsv" 3 "Top User-Agent"
    top_count_from_col "$tsv" 4 "Top Status Code"
    top_count_from_col "$tsv" 5 "Top HTTP Method"
    top_count_from_col "$tsv" 6 "Pico por minuto"
    echo
    echo "Top endpoints suspeitos (login/admin/xmlrpc/phpmyadmin/.env):"
    find_suspicious_endpoints "$tsv" || true
  } | tee "$report_txt"

  local ip_top url_top ua_top status_top method_top minute_top
  ip_top="$(awk -F'\t' '$1 != "-" && $1 != "" {print $1}' "$tsv" | sort | uniq -c | sort -nr | head -n1 | sed 's/^[[:space:]]*//' || true)"
  url_top="$(awk -F'\t' '$2 != "-" && $2 != "" {print $2}' "$tsv" | sort | uniq -c | sort -nr | head -n1 | sed 's/^[[:space:]]*//' || true)"
  ua_top="$(awk -F'\t' '$3 != "-" && $3 != "" {print $3}' "$tsv" | sort | uniq -c | sort -nr | head -n1 | sed 's/^[[:space:]]*//' || true)"
  status_top="$(awk -F'\t' '$4 != "-" && $4 != "" {print $4}' "$tsv" | sort | uniq -c | sort -nr | head -n1 | sed 's/^[[:space:]]*//' || true)"
  method_top="$(awk -F'\t' '$5 != "-" && $5 != "" {print $5}' "$tsv" | sort | uniq -c | sort -nr | head -n1 | sed 's/^[[:space:]]*//' || true)"
  minute_top="$(awk -F'\t' '$6 != "-" && $6 != "" {print $6}' "$tsv" | sort | uniq -c | sort -nr | head -n1 | sed 's/^[[:space:]]*//' || true)"

  cat >"$report_json" <<EOF
{
  "file": "$(printf '%s' "$file" | json_escape)",
  "detected_format": "$(printf '%s' "$format" | json_escape)",
  "generated_at": "$(date -Is)",
  "top_ip": "$(printf '%s' "${ip_top:-sem_dados}" | json_escape)",
  "top_url": "$(printf '%s' "${url_top:-sem_dados}" | json_escape)",
  "top_user_agent": "$(printf '%s' "${ua_top:-sem_dados}" | json_escape)",
  "top_status_code": "$(printf '%s' "${status_top:-sem_dados}" | json_escape)",
  "top_http_method": "$(printf '%s' "${method_top:-sem_dados}" | json_escape)",
  "peak_per_minute": "$(printf '%s' "${minute_top:-sem_dados}" | json_escape)"
}
EOF

  rm -f "$tsv"
  info "Relatorio texto: $report_txt"
  info "Relatorio JSON:  $report_json"
}

hunt_mode() {
  local file
  file="$(resolve_path "$1")"
  [[ -f "$file" ]] || die "Arquivo nao encontrado: $file"
  [[ -r "$file" ]] || die "Sem permissao de leitura: $file"

  local dir base ts out
  dir="$(dirname "$file")"
  base="$(basename "$file")"
  ts="$(date +%Y%m%d_%H%M%S)"
  out="${dir}/${base}.hunt_${ts}.txt"

  build_hunt_report "$file" | tee "$out"
  info "Relatorio IOC/Hunt: $out"
}

regex_filter_txt() {
  local regex="$1"
  local target_path
  target_path="$(resolve_path "$2")"
  [[ -n "$regex" ]] || die "Regex vazia."
  [[ -e "$target_path" ]] || die "Caminho nao encontrado: $target_path"

  if [[ -f "$target_path" ]]; then
    [[ "$target_path" == *.txt ]] || die "Arquivo deve ser .txt: $target_path"
    info "Filtrando em arquivo: $target_path"
    grep -En "$regex" "$target_path" || true
    return
  fi

  if [[ -d "$target_path" ]]; then
    info "Filtrando em diretorio recursivo (.txt): $target_path"
    grep -ERn --include="*.txt" "$regex" "$target_path" || true
    return
  fi

  die "Informe um arquivo .txt ou diretorio valido."
}

print_menu() {
  cat <<'EOF'
========================================
         Red Team Helper v2
========================================
1) Manutencao (apt update + dist-upgrade)
2) Analise de logs (IP, URL, UA, status, metodo, pico/min)
3) Hunt de IOC/Flags (hash, url, ip, dominio)
4) Filtro Regex em .txt
5) Sair
EOF
}

interactive_menu() {
  while true; do
    print_menu
    read -r -p "Escolha [1-5]: " opt
    case "${opt:-}" in
      1)
        run_maintenance
        ;;
      2)
        read -r -p "Caminho do arquivo de log: " file
        analyze_logs "$file"
        ;;
      3)
        read -r -p "Caminho do arquivo para hunt: " file
        hunt_mode "$file"
        ;;
      4)
        read -r -p "Regex (grep -E): " rgx
        read -r -p "Arquivo .txt ou diretorio: " target
        regex_filter_txt "$rgx" "$target"
        ;;
      5)
        exit 0
        ;;
      *)
        warn "Opcao invalida."
        ;;
    esac
    echo
  done
}

main() {
  require_cmds

  if (($# == 0)); then
    interactive_menu
    return
  fi

  case "$1" in
    --help|-h)
      usage
      ;;
    --maintain)
      run_maintenance
      ;;
    --analyze)
      [[ $# -ge 2 ]] || die "Uso: $SCRIPT_NAME --analyze <arquivo_log>"
      analyze_logs "$2"
      ;;
    --hunt)
      [[ $# -ge 2 ]] || die "Uso: $SCRIPT_NAME --hunt <arquivo_log>"
      hunt_mode "$2"
      ;;
    --regex)
      [[ $# -ge 3 ]] || die "Uso: $SCRIPT_NAME --regex \"<padrao>\" <arquivo_ou_diretorio_txt>"
      regex_filter_txt "$2" "$3"
      ;;
    *)
      die "Opcao invalida: $1 (use --help)"
      ;;
  esac
}

main "$@"
