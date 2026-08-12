# Formatos, normalização e relatórios

## Contrato normalizado

Os parsers convertem cada linha em oito campos TSV internos:

| Posição | Campo | Uso |
| ---: | --- | --- |
| 1 | `ip` | cliente, origem ou primeiro IPv4 reconhecido |
| 2 | `url` | caminho, URI ou URL |
| 3 | `user_agent` | agente do cliente |
| 4 | `status` | status HTTP |
| 5 | `method` | método HTTP |
| 6 | `minute` | timestamp truncado por minuto |
| 7 | `state` | `parsed`, `invalid` ou `blank` |
| 8 | `reason` | motivo de falha ou variante reconhecida |

Campos ausentes recebem `-`. Tabs e quebras de linha em valores JSON são
substituídos por espaços para preservar o contrato TSV.

## Apache

Aceita linhas Common e Combined com:

- host/IP no primeiro campo;
- timestamp entre colchetes;
- request entre aspas, com método e URL;
- status HTTP de três dígitos;
- User-Agent no campo Combined, quando presente.

Exemplo:

```text
192.0.2.10 - - [12/Aug/2026:10:00:01 -0300] "GET / HTTP/1.1" 200 120 "-" "lab-browser/1.0"
```

Motivos de falha: `missing_or_invalid_timestamp`,
`missing_or_invalid_request` e `missing_or_invalid_status`.

Formatos Apache personalizados, campos com aspas não escapadas e registros
multilinha podem exigir pré-normalização.

## JSON Lines

A entrada precisa conter um objeto JSON completo por linha. Arrays globais,
JSON pretty-printed em várias linhas e valores que não sejam objetos são
considerados inválidos.

Aliases reconhecidos:

| Campo normalizado | Chaves de entrada, em ordem de precedência |
| --- | --- |
| IP | `ip`, `client_ip`, `remote_ip`, `remote_addr`, `source.ip`, `client.ip` |
| URL | `url.path`, `url.full`, `url`, `path`, `uri`, `request_uri` |
| User-Agent | `user_agent.original`, `user_agent`, `ua`, `http_user_agent` |
| método | `method`, `http_method`, `http.request.method` |
| status | `status`, `status_code`, `http_status`, `http.response.status_code` |
| timestamp | `timestamp`, `time`, `@timestamp`, `event.created` |

Um objeto JSON válido sem nenhum dos campos centrais recebe
`unsupported_schema`. JSON inválido recebe `invalid_json`.

## Syslog

Reconhece cabeçalhos:

- RFC3164, como `Aug 12 10:00:01 host app[123]: ...`;
- RFC5424, como `<134>1 2026-08-12T13:00:01Z host app 123 ID47 - ...`.

Dentro da mensagem, procura campos comuns:

- IP: `src=`, `client_ip=`, `source_ip=` ou primeiro IPv4;
- URL: `path=`, `uri=`, `url=` ou request HTTP entre aspas;
- método: `method=` ou verbo HTTP conhecido;
- status: `status=` ou código HTTP separado por espaços;
- User-Agent: `ua="..."` ou `user_agent="..."`.

Uma linha com cabeçalho syslog válido pode ser processada sem conter campos
HTTP. Isso permite medir o volume temporal e IPs em logs de autenticação. Uma
linha sem cabeçalho reconhecido recebe `invalid_syslog_header`.

O ano não existe no cabeçalho RFC3164 e não é inferido pela ferramenta.

## Detecção automática

Até 50 linhas não vazias são pontuadas:

- objetos JSON válidos favorecem `jsonl`;
- timestamp, request entre aspas e status favorecem `apache`;
- cabeçalho RFC3164 ou RFC5424 favorece `syslog`.

O maior score vence. Empate ou score zero retorna `unknown`; nesse caso, use
`--format` para declarar o parser conscientemente.

## JSON de análise

Campos de topo:

- `schema_version`: versão do contrato do relatório;
- `tool`: nome e versão do executável;
- `report_type`: `log_analysis`;
- `generated_at`: UTC ISO 8601;
- `input`: fonte informada e formato selecionado;
- `summary`: qualidade de ingestão;
- `rankings`: listas `{value,count}`;
- `quality.invalid_reasons`: falhas de parsing agrupadas.

`--top` limita cada lista, mas não altera as contagens do resumo.

## JSON de hunting

Usa `report_type: indicator_hunt`, resumo com indicadores únicos e ocorrências
totais e grupos `flags`, `hashes`, `urls`, `ips` e `domains`.

Os extratores são sintáticos. Eles não validam reputação, roteabilidade,
propriedade ou relevância de um candidato.

## Reprodutibilidade

Fixtures em `fixtures/` usam os blocos de documentação `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24` e domínios `.test`. Os arquivos completos
esperados, exceto timestamp e caminho dinâmicos, estão em `tests/expected/`.
