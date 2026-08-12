# Arquitetura e catálogo de funções

## Fluxo

```text
CLI -> validação -> entrada/STDIN -> detecção -> normalização TSV
    -> modelo JSON -> render text/JSON/CSV -> publicação atômica
```

A separação permanece propositalmente pequena: um entrypoint e três módulos.
As bibliotecas são carregadas com `source`; não existe sistema de plugins ou
framework interno.

## `redteam_helper.sh`

| Função | Contrato |
| --- | --- |
| `usage` | Imprime ajuda global. Não valida dependências. |
| `analyze_usage` | Imprime opções e exemplos de `analyze`. |
| `hunt_usage` | Imprime opções de `hunt`. |
| `regex_usage` | Imprime opções e garantias de `regex`. |
| `analyze_command` | Faz parsing da CLI, prepara entrada, detecta formato e chama `analyze_logs`. |
| `hunt_command` | Faz parsing da CLI, prepara entrada e chama `hunt_file`. |
| `regex_command` | Monta argumentos seguros de `grep` e executa busca somente leitura. |
| `print_menu` | Renderiza o menu interativo sem funções privilegiadas. |
| `interactive_menu` | Lê escolhas do TTY e delega aos três comandos. |
| `main` | Roteia comando, aliases, ajuda e versão. |

## `lib/common.sh`

| Função | Contrato e efeitos |
| --- | --- |
| `info` | Escreve mensagem informativa no stderr, exceto com `--quiet`. |
| `warn` | Escreve aviso no stderr. |
| `die` | Escreve erro e encerra com o código recebido. |
| `on_error` | Informa código e linha de uma falha inesperada. |
| `register_temp_file` | Registra caminho criado pela ferramenta para limpeza posterior. |
| `cleanup_temp_files` | Remove somente temporários registrados pelo processo Bash principal. |
| `new_temp_file` | Cria arquivo com `mktemp` no `TMPDIR` ou `/tmp`. |
| `require_option_value` | Rejeita opção que não recebeu argumento. |
| `require_commands` | Verifica executáveis e encerra com código 4 se faltarem. |
| `validate_positive_integer` | Valida opções numéricas como `--top`. |
| `validate_format` | Aceita somente `auto`, `apache`, `jsonl` e `syslog`. |
| `parse_output_formats` | Valida, deduplica e preenche `OUTPUT_FORMATS`. |
| `resolve_path` | Resolve cwd, caminho absoluto e `REDTEAM_BASE_DIR`. |
| `prepare_input` | Valida arquivo ou materializa stdin; define arquivo e label globais. |
| `sanitize_stem` | Converte o nome da fonte em componente seguro de filename. |
| `current_timestamp` | Retorna UTC no formato ISO 8601. |
| `prepare_output_directory` | Cria o destino e verifica que é gravável. |
| `assert_output_available` | Impede colisão sem autorização `--force`. |
| `create_output_temp` | Cria temporário no mesmo diretório do artefato final. |
| `publish_output` | Move o arquivo completo ao destino e registra o artefato. |
| `run_grep_allow_no_match` | Trata status 1 do grep como ausência válida de matches. |

`cleanup_temp_files` verifica `BASH_SUBSHELL` e `BASHPID` para impedir que traps
herdados por command substitutions apaguem temporários ainda usados pelo
processo principal.

## `lib/parsers.sh`

| Função | Contrato |
| --- | --- |
| `detect_log_format` | Pontua amostra e retorna `apache`, `jsonl`, `syslog` ou `unknown`. |
| `normalize_apache` | Converte cada linha Apache em oito colunas TSV. |
| `normalize_jsonl` | Usa `jq` para parse real, aliases e normalização TSV. |
| `normalize_syslog` | Reconhece RFC3164/RFC5424 e campos comuns da mensagem. |
| `normalize_log` | Dispatcher que seleciona exatamente um normalizador. |

Todo parser produz um registro TSV inclusive para linha vazia ou inválida.
Isso faz a soma `parsed + invalid + blank` corresponder ao total observado.

## `lib/reports.sh`

| Função | Contrato e efeitos |
| --- | --- |
| `build_analysis_json` | Agrupa TSV em resumo, rankings e qualidade no modelo JSON. |
| `render_analysis_text` | Converte o modelo JSON em relatório humano. |
| `render_analysis_csv` | Exporta eventos TSV processados para CSV com quoting. |
| `assert_requested_outputs` | Verifica antecipadamente todas as colisões solicitadas. |
| `publish_analysis_reports` | Renderiza e publica cada formato de análise. |
| `analyze_logs` | Coordena normalização, modelo, validação e exportação. |
| `append_counted_matches` | Extrai, ordena e conta um tipo de candidato. |
| `build_hunt_tsv` | Constrói tabela de flags, hashes, URLs, IPs e domínios. |
| `build_hunt_json` | Converte candidatos TSV no modelo JSON de hunting. |
| `render_hunt_text` | Produz representação humana do hunting. |
| `render_hunt_csv` | Produz CSV `type,value,count`. |
| `publish_hunt_reports` | Renderiza e publica formatos solicitados do hunting. |
| `hunt_file` | Coordena extração, modelo, validação e exportação. |

O JSON é sempre construído e validado internamente, mesmo quando o operador
solicita apenas texto ou CSV. Isso mantém uma única fonte para métricas.

## Invariantes de segurança

1. Nenhuma função escreve no caminho da entrada.
2. Saídas existentes só podem ser substituídas com `--force`.
3. Relatórios são publicados com `mv` a partir do mesmo diretório.
4. Caminhos e padrões são passados como argumentos quoted.
5. O comando regex usa `-e` para o padrão e `--` antes do alvo.
6. Não existem comandos de elevação, instalação ou manutenção no runtime.

## Como estender

Para um novo formato:

1. adicionar `normalize_<formato>` preservando as oito colunas;
2. incluir a assinatura em `detect_log_format`;
3. adicionar o valor em `validate_format` e `normalize_log`;
4. criar fixture válida, casos malformados e JSON esperado;
5. documentar campos e limitações;
6. executar `bash scripts/check.sh`.

Evite abstrações novas enquanto o contrato TSV e as três bibliotecas forem
suficientes.
