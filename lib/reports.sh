#!/usr/bin/env bash

# Geração atômica de relatórios de análise e hunting.

build_analysis_json() {
  local normalized="$1"
  local input_label="$2"
  local format="$3"
  local top="$4"
  local generated_at="$5"
  local output="$6"

  jq -Rn \
    --arg schema_version "1.0" \
    --arg tool_version "$VERSION" \
    --arg generated_at "$generated_at" \
    --arg input_source "$input_label" \
    --arg detected_format "$format" \
    --argjson top "$top" \
    --rawfile data "$normalized" '
      def rows:
        $data | split("\n") | map(select(length > 0) | split("\t"));
      def ranked($values; $limit):
        $values
        | map(select(. != "-" and . != ""))
        | sort
        | group_by(.)
        | map({value: .[0], count: length})
        | sort_by(-.count, .value)
        | .[:$limit];
      (rows) as $rows
      | ($rows | map(select(.[6] == "parsed"))) as $parsed
      | {
          schema_version: $schema_version,
          tool: {name: "redteam-helper", version: $tool_version},
          report_type: "log_analysis",
          generated_at: $generated_at,
          input: {source: $input_source, format: $detected_format},
          summary: {
            total_lines: ($rows | length),
            parsed_lines: ($parsed | length),
            invalid_lines: ($rows | map(select(.[6] == "invalid")) | length),
            blank_lines: ($rows | map(select(.[6] == "blank")) | length)
          },
          rankings: {
            top_ips: ranked([$parsed[] | .[0]]; $top),
            top_urls: ranked([$parsed[] | .[1]]; $top),
            top_user_agents: ranked([$parsed[] | .[2]]; $top),
            top_status_codes: ranked([$parsed[] | .[3]]; $top),
            top_http_methods: ranked([$parsed[] | .[4]]; $top),
            peak_minutes: ranked([$parsed[] | .[5]]; $top),
            suspicious_endpoints: ranked(
              [$parsed[] | .[1] | select(test("/(login|wp-login|xmlrpc|admin|phpmyadmin|\\.env)"; "i"))];
              $top
            )
          },
          quality: {
            invalid_reasons: ranked([$rows[] | select(.[6] == "invalid") | .[7]]; $top)
          }
        }
    ' >"$output"
}

render_analysis_text() {
  local json="$1"
  local output="$2"

  jq -r '
    def items($values):
      if ($values | length) == 0 then "  sem dados"
      else $values | map("  \(.count)x \(.value)") | join("\n")
      end;
    "RedTeam Helper - Relatório de análise",
    "=====================================",
    "Fonte: \(.input.source)",
    "Formato: \(.input.format)",
    "Gerado em: \(.generated_at)",
    "",
    "Resumo",
    "  Linhas totais: \(.summary.total_lines)",
    "  Linhas processadas: \(.summary.parsed_lines)",
    "  Linhas inválidas: \(.summary.invalid_lines)",
    "  Linhas vazias: \(.summary.blank_lines)",
    "",
    "Top IPs", items(.rankings.top_ips), "",
    "Top URLs", items(.rankings.top_urls), "",
    "Top User-Agents", items(.rankings.top_user_agents), "",
    "Top status HTTP", items(.rankings.top_status_codes), "",
    "Top métodos HTTP", items(.rankings.top_http_methods), "",
    "Picos por minuto", items(.rankings.peak_minutes), "",
    "Endpoints de interesse defensivo", items(.rankings.suspicious_endpoints), "",
    "Falhas de parsing", items(.quality.invalid_reasons)
  ' "$json" >"$output"
}

render_analysis_csv() {
  local normalized="$1"
  local output="$2"

  awk -F'\t' '
    function quote(value) {
      gsub(/"/, "\"\"", value)
      return "\"" value "\""
    }
    BEGIN { print "ip,url,user_agent,status,method,minute" }
    $7 == "parsed" {
      print quote($1) "," quote($2) "," quote($3) "," quote($4) "," \
        quote($5) "," quote($6)
    }
  ' "$normalized" >"$output"
}

assert_requested_outputs() {
  local base_path="$1"
  local force="$2"
  local format
  local extension

  for format in "${OUTPUT_FORMATS[@]}"; do
    case "$format" in
      text) extension="txt" ;;
      json) extension="json" ;;
      csv) extension="csv" ;;
    esac
    assert_output_available "${base_path}.${extension}" "$force"
  done
}

publish_analysis_reports() {
  local normalized="$1"
  local json_model="$2"
  local base_path="$3"
  local format
  local destination

  GENERATED_REPORTS=()
  for format in "${OUTPUT_FORMATS[@]}"; do
    case "$format" in
      text)
        destination="${base_path}.txt"
        create_output_temp "$destination"
        render_analysis_text "$json_model" "$OUTPUT_TEMP"
        publish_output "$OUTPUT_TEMP" "$destination"
        ;;
      json)
        destination="${base_path}.json"
        create_output_temp "$destination"
        cp -- "$json_model" "$OUTPUT_TEMP"
        publish_output "$OUTPUT_TEMP" "$destination"
        ;;
      csv)
        destination="${base_path}.csv"
        create_output_temp "$destination"
        render_analysis_csv "$normalized" "$OUTPUT_TEMP"
        publish_output "$OUTPUT_TEMP" "$destination"
        ;;
    esac
  done
}

analyze_logs() {
  local input_file="$1"
  local input_label="$2"
  local format="$3"
  local output_dir="$4"
  local top="$5"
  local force="$6"
  local normalized
  local json_model
  local stem
  local base_path
  local report

  normalized="$(new_temp_file)"
  register_temp_file "$normalized"
  json_model="$(new_temp_file)"
  register_temp_file "$json_model"

  normalize_log "$input_file" "$format" "$normalized"
  [[ -s "$normalized" ]] || die "$EXIT_FORMAT" "O parser não produziu registros."

  prepare_output_directory "$output_dir"
  stem="$(sanitize_stem "$input_label")"
  base_path="${output_dir%/}/${stem}.analysis"
  assert_requested_outputs "$base_path" "$force"

  build_analysis_json "$normalized" "$input_label" "$format" "$top" \
    "$(current_timestamp)" "$json_model"
  jq -e . "$json_model" >/dev/null || die "$EXIT_FORMAT" \
    "Falha ao validar o modelo JSON do relatório."
  publish_analysis_reports "$normalized" "$json_model" "$base_path"

  for report in "${GENERATED_REPORTS[@]}"; do
    info "Artefato gerado: $report"
  done
}

append_counted_matches() {
  local type="$1"
  local pattern="$2"
  local file="$3"
  local output="$4"

  { grep -Eo -I -e "$pattern" -- "$file" || true; } \
    | sort \
    | uniq -c \
    | sort -nr \
    | awk -v type="$type" '
        {
          count=$1
          sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "")
          gsub(/\t/, " ")
          print type "\t" $0 "\t" count
        }
      ' >>"$output"
}

build_hunt_tsv() {
  local file="$1"
  local output="$2"

  : >"$output"
  append_counted_matches "flag" '(flag|ctf)\{[^}[:cntrl:]]+\}' "$file" "$output"
  append_counted_matches "hash" '([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})' "$file" "$output"
  append_counted_matches "url" 'https?://[^"[:space:]<>]+' "$file" "$output"
  append_counted_matches "ip" '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" "$output"
  append_counted_matches "domain" '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}' "$file" "$output"
}

build_hunt_json() {
  local indicators="$1"
  local input_label="$2"
  local top="$3"
  local generated_at="$4"
  local output="$5"

  jq -Rn \
    --arg tool_version "$VERSION" \
    --arg generated_at "$generated_at" \
    --arg input_source "$input_label" \
    --argjson top "$top" \
    --rawfile data "$indicators" '
      def rows:
        $data | split("\n") | map(select(length > 0) | split("\t"));
      def indicators($rows; $type; $limit):
        $rows
        | map(select(.[0] == $type) | {value: .[1], count: (.[2] | tonumber)})
        | sort_by(-.count, .value)
        | .[:$limit];
      (rows) as $rows
      | {
          schema_version: "1.0",
          tool: {name: "redteam-helper", version: $tool_version},
          report_type: "indicator_hunt",
          generated_at: $generated_at,
          input: {source: $input_source},
          summary: {
            unique_indicators: ($rows | length),
            total_hits: ([$rows[] | .[2] | tonumber] | add // 0)
          },
          indicators: {
            flags: indicators($rows; "flag"; $top),
            hashes: indicators($rows; "hash"; $top),
            urls: indicators($rows; "url"; $top),
            ips: indicators($rows; "ip"; $top),
            domains: indicators($rows; "domain"; $top)
          }
        }
    ' >"$output"
}

render_hunt_text() {
  local json="$1"
  local output="$2"

  jq -r '
    def items($values):
      if ($values | length) == 0 then "  sem dados"
      else $values | map("  \(.count)x \(.value)") | join("\n")
      end;
    "RedTeam Helper - Hunt de indicadores",
    "====================================",
    "Fonte: \(.input.source)",
    "Gerado em: \(.generated_at)",
    "Indicadores únicos: \(.summary.unique_indicators)",
    "Ocorrências totais: \(.summary.total_hits)", "",
    "Flags", items(.indicators.flags), "",
    "Hashes", items(.indicators.hashes), "",
    "URLs", items(.indicators.urls), "",
    "IPs", items(.indicators.ips), "",
    "Domínios", items(.indicators.domains)
  ' "$json" >"$output"
}

render_hunt_csv() {
  local indicators="$1"
  local output="$2"

  awk -F'\t' '
    function quote(value) {
      gsub(/"/, "\"\"", value)
      return "\"" value "\""
    }
    BEGIN { print "type,value,count" }
    { print quote($1) "," quote($2) "," $3 }
  ' "$indicators" >"$output"
}

publish_hunt_reports() {
  local indicators="$1"
  local json_model="$2"
  local base_path="$3"
  local format
  local destination

  GENERATED_REPORTS=()
  for format in "${OUTPUT_FORMATS[@]}"; do
    case "$format" in
      text)
        destination="${base_path}.txt"
        create_output_temp "$destination"
        render_hunt_text "$json_model" "$OUTPUT_TEMP"
        publish_output "$OUTPUT_TEMP" "$destination"
        ;;
      json)
        destination="${base_path}.json"
        create_output_temp "$destination"
        cp -- "$json_model" "$OUTPUT_TEMP"
        publish_output "$OUTPUT_TEMP" "$destination"
        ;;
      csv)
        destination="${base_path}.csv"
        create_output_temp "$destination"
        render_hunt_csv "$indicators" "$OUTPUT_TEMP"
        publish_output "$OUTPUT_TEMP" "$destination"
        ;;
    esac
  done
}

hunt_file() {
  local input_file="$1"
  local input_label="$2"
  local output_dir="$3"
  local top="$4"
  local force="$5"
  local indicators
  local json_model
  local stem
  local base_path
  local report

  indicators="$(new_temp_file)"
  register_temp_file "$indicators"
  json_model="$(new_temp_file)"
  register_temp_file "$json_model"
  build_hunt_tsv "$input_file" "$indicators"

  prepare_output_directory "$output_dir"
  stem="$(sanitize_stem "$input_label")"
  base_path="${output_dir%/}/${stem}.hunt"
  assert_requested_outputs "$base_path" "$force"

  build_hunt_json "$indicators" "$input_label" "$top" \
    "$(current_timestamp)" "$json_model"
  jq -e . "$json_model" >/dev/null || die "$EXIT_FORMAT" \
    "Falha ao validar o modelo JSON do hunting."
  publish_hunt_reports "$indicators" "$json_model" "$base_path"

  for report in "${GENERATED_REPORTS[@]}"; do
    info "Artefato gerado: $report"
  done
}
