#!/usr/bin/env bash

# Detecção e normalização de Apache, JSON Lines e syslog.
# Contrato TSV interno:
# ip, url, user_agent, status, method, minute, state, reason

detect_log_format() {
  local file="$1"
  local json_score
  local apache_score
  local syslog_score
  local best
  local format="unknown"

  json_score="$(awk 'NF {print; count++} count == 50 {exit}' "$file" \
    | jq -Rrc 'fromjson? | objects | 1' 2>/dev/null \
    | awk '{sum += $1} END {print sum + 0}')"
  apache_score="$(awk 'NF && count < 50 {count++; if ($0 ~ /\[[^]]+\][[:space:]]+"[A-Z-]+[[:space:]][^"]*"[[:space:]]+[1-5][0-9][0-9]/) score++} END {print score + 0}' "$file")"
  syslog_score="$(awk 'NF && count < 50 {count++; if ($0 ~ /^<[0-9]+>[1-9][0-9]*[[:space:]]/ || $0 ~ /^[A-Z][a-z]{2}[[:space:]][ 0-9][0-9][[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]/) score++} END {print score + 0}' "$file")"

  best=0
  if ((json_score > best)); then
    best="$json_score"
    format="jsonl"
  fi
  if ((apache_score > best)); then
    best="$apache_score"
    format="apache"
  elif ((apache_score == best && apache_score > 0)); then
    format="unknown"
  fi
  if ((syslog_score > best)); then
    best="$syslog_score"
    format="syslog"
  elif ((syslog_score == best && syslog_score > 0)); then
    format="unknown"
  fi

  printf '%s\n' "$format"
}

normalize_apache() {
  local file="$1"
  local output="$2"

  awk '
    BEGIN { OFS="\t" }
    function clean(value) {
      gsub(/[\t\r\n]/, " ", value)
      return value == "" ? "-" : value
    }
    function emit(ip, url, ua, status, method, minute, state, reason) {
      print clean(ip), clean(url), clean(ua), clean(status), clean(method), \
        clean(minute), state, reason
    }
    /^[[:space:]]*$/ {
      emit("-", "-", "-", "-", "-", "-", "blank", "empty_line")
      next
    }
    {
      ip=$1; url="-"; ua="-"; status="-"; method="-"; minute="-"
      timestamp_ok=0; request_ok=0; status_ok=0

      if (match($0, /\[[^]]+\]/)) {
        ts=substr($0, RSTART + 1, RLENGTH - 2)
        split(ts, timestamp_parts, " ")
        if (length(timestamp_parts[1]) >= 17) {
          minute=substr(timestamp_parts[1], 1, 17)
          timestamp_ok=1
        }
      }

      quoted_count=split($0, quoted, "\"")
      if (quoted_count >= 3) {
        request=quoted[2]
        if (request == "-") {
          request_ok=1
        } else {
          split(request, request_parts, /[[:space:]]+/)
          if (length(request_parts) >= 2 && request_parts[1] ~ /^[A-Z-]+$/) {
            method=request_parts[1]
            url=request_parts[2]
            request_ok=1
          }
        }

        remainder=quoted[3]
        gsub(/^[[:space:]]+/, "", remainder)
        split(remainder, remainder_parts, /[[:space:]]+/)
        if (remainder_parts[1] ~ /^[1-5][0-9][0-9]$/) {
          status=remainder_parts[1]
          status_ok=1
        }
      }
      if (quoted_count >= 7) ua=quoted[6]

      if (timestamp_ok && request_ok && status_ok) {
        emit(ip, url, ua, status, method, minute, "parsed", "-")
      } else {
        reason="invalid_apache_record"
        if (!timestamp_ok) reason="missing_or_invalid_timestamp"
        else if (!request_ok) reason="missing_or_invalid_request"
        else if (!status_ok) reason="missing_or_invalid_status"
        emit("-", "-", "-", "-", "-", "-", "invalid", reason)
      }
    }
  ' "$file" >"$output"
}

normalize_jsonl() {
  local file="$1"
  local output="$2"

  jq -Rr '
    def clean:
      if . == null or . == "" then "-"
      else tostring | gsub("[\\t\\r\\n]"; " ")
      end;
    def child($value; $key):
      if ($value | type) == "object" then $value[$key] else null end;
    def minute:
      clean as $value
      | if $value == "-" or ($value | length) < 16 then "-"
        else $value[0:16]
        end;
    if test("^[[:space:]]*$") then
      ["-", "-", "-", "-", "-", "-", "blank", "empty_line"]
    else
      (try fromjson catch null) as $event
      | if ($event | type) != "object" then
          ["-", "-", "-", "-", "-", "-", "invalid", "invalid_json"]
        else
          ($event.ip // $event.client_ip // $event.remote_ip // $event.remote_addr
            // child($event.source; "ip") // child($event.client; "ip")) as $ip
          | (child($event.url; "path") // child($event.url; "full") // $event.url // $event.path
            // $event.uri // $event.request_uri) as $url
          | (child($event.user_agent; "original") // $event.user_agent // $event.ua
            // $event.http_user_agent) as $ua
          | ($event.method // $event.http_method
            // child(child($event.http; "request"); "method")) as $method
          | ($event.status // $event.status_code // $event.http_status
            // child(child($event.http; "response"); "status_code")) as $status
          | ($event.timestamp // $event.time // $event["@timestamp"]
            // child($event.event; "created")) as $timestamp
          | if [$ip, $url, $method, $status, $timestamp] | all(. == null) then
              ["-", "-", "-", "-", "-", "-", "invalid", "unsupported_schema"]
            else
              [($ip | clean), ($url | clean), ($ua | clean), ($status | clean),
                ($method | clean), ($timestamp | minute), "parsed", "-"]
            end
        end
    end
    | @tsv
  ' "$file" >"$output"
}

normalize_syslog() {
  local file="$1"
  local output="$2"

  awk '
    BEGIN { OFS="\t" }
    function clean(value) {
      gsub(/[\t\r\n]/, " ", value)
      return value == "" ? "-" : value
    }
    function emit(ip, url, ua, status, method, minute, state, reason) {
      print clean(ip), clean(url), clean(ua), clean(status), clean(method), \
        clean(minute), state, reason
    }
    function key_value(line, key,    pattern, value) {
      pattern=key "=[^[:space:]]+"
      if (match(line, pattern)) {
        value=substr(line, RSTART + length(key) + 1, RLENGTH - length(key) - 1)
        gsub(/^"|"$/, "", value)
        return value
      }
      return "-"
    }
    /^[[:space:]]*$/ {
      emit("-", "-", "-", "-", "-", "-", "blank", "empty_line")
      next
    }
    {
      ip="-"; url="-"; ua="-"; status="-"; method="-"; minute="-"
      header=""

      if ($0 ~ /^<[0-9]+>[1-9][0-9]*[[:space:]]/) {
        header="rfc5424"
        split($0, fields, /[[:space:]]+/)
        if (length(fields[2]) >= 16) minute=substr(fields[2], 1, 16)
      } else if ($0 ~ /^[A-Z][a-z]{2}[[:space:]][ 0-9][0-9][[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]/) {
        header="rfc3164"
        minute=substr($0, 1, 12)
        gsub(/[[:space:]]+/, " ", minute)
      }

      ip=key_value($0, "src")
      if (ip == "-") ip=key_value($0, "client_ip")
      if (ip == "-") ip=key_value($0, "source_ip")
      if (ip == "-" && match($0, /([0-9]{1,3}\.){3}[0-9]{1,3}/))
        ip=substr($0, RSTART, RLENGTH)

      method=key_value($0, "method")
      url=key_value($0, "path")
      if (url == "-") url=key_value($0, "uri")
      if (url == "-") url=key_value($0, "url")
      status=key_value($0, "status")

      if (match($0, /"(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH)[[:space:]][^"]+"/)) {
        request=substr($0, RSTART + 1, RLENGTH - 2)
        split(request, request_parts, /[[:space:]]+/)
        if (method == "-") method=request_parts[1]
        if (url == "-") url=request_parts[2]
      }
      if (method == "-" && match($0, /(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH)/))
        method=substr($0, RSTART, RLENGTH)
      if (status == "-" && match($0, /[[:space:]][1-5][0-9][0-9]([[:space:]]|$)/)) {
        status=substr($0, RSTART + 1, 3)
      }

      if (match($0, /(ua|user_agent)="[^"]*"/)) {
        ua=substr($0, RSTART, RLENGTH)
        sub(/^[^=]+=/, "", ua)
        gsub(/^"|"$/, "", ua)
      }

      if (header != "")
        emit(ip, url, ua, status, method, minute, "parsed", header)
      else
        emit("-", "-", "-", "-", "-", "-", "invalid", "invalid_syslog_header")
    }
  ' "$file" >"$output"
}

normalize_log() {
  local file="$1"
  local format="$2"
  local output="$3"

  case "$format" in
    apache) normalize_apache "$file" "$output" ;;
    jsonl) normalize_jsonl "$file" "$output" ;;
    syslog) normalize_syslog "$file" "$output" ;;
    *) die "$EXIT_FORMAT" "Parser não implementado para o formato: $format" ;;
  esac
}
