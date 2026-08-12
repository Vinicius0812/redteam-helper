# Release demonstrável v0.2.0

Este documento prepara a release; publicar tag ou GitHub Release continua sendo
uma ação explícita do mantenedor.

## Gate de qualidade

```bash
bash scripts/check.sh
test "$(cat VERSION)" = "0.2.0"
./redteam_helper.sh --version
```

O gate precisa concluir sintaxe Bash, ShellCheck e todos os testes Bats sem
warnings ou falhas.

## Demonstração reproduzível

Execute em um checkout limpo:

```bash
./redteam_helper.sh analyze \
  --output text,json,csv \
  --output-dir ./demo-artifacts-v0.2.0 \
  fixtures/apache.log

./redteam_helper.sh analyze \
  --output json \
  --output-dir ./demo-artifacts-v0.2.0 \
  fixtures/events.jsonl

./redteam_helper.sh analyze \
  --output json \
  --output-dir ./demo-artifacts-v0.2.0 \
  fixtures/syslog-rfc5424.log

./redteam_helper.sh hunt \
  --output text,json,csv \
  --output-dir ./demo-artifacts-v0.2.0 \
  fixtures/hunt.txt

jq '.summary, .rankings.suspicious_endpoints' \
  demo-artifacts-v0.2.0/apache.analysis.json
```

Escolha um diretório novo para cada demonstração. Se ele já contiver os mesmos
artefatos, a ferramenta falhará com segurança; use outro diretório ou autorize
explicitamente a substituição com `--force`.

Resultados determinísticos, excluindo `generated_at` e o label da fonte, estão
em `tests/expected/` e são comparados automaticamente pelos testes.

## Checklist do mantenedor

- [ ] working tree revisada e sem artefatos locais;
- [ ] `VERSION`, `--version` e changelog indicam `0.2.0`;
- [ ] CI verde no commit que receberá a tag;
- [ ] fixtures confirmadas como fictícias;
- [ ] README e notas de migração revisados;
- [ ] tag anotada `v0.2.0` criada no commit validado;
- [ ] GitHub Release criada com o resumo abaixo;
- [ ] instalação e demonstração repetidas a partir do tarball da release.

## Notas sugeridas

> RedTeam Helper v0.2.0 reposiciona o projeto como ferramenta Bash de triagem
> defensiva reproduzível. A release remove manutenção privilegiada, adiciona
> parsers testados para Apache, JSON Lines e syslog, exporta texto/JSON/CSV e
> inclui fixtures fictícias, resultados esperados, ShellCheck, Bats e CI.

## Migração da versão anterior

| Antes | v0.2.0 |
| --- | --- |
| `--analyze arquivo` | ainda aceito; prefira `analyze arquivo` |
| `--hunt arquivo` | ainda aceito; prefira `hunt arquivo` |
| `--regex padrão alvo` | ainda aceito; prefira `regex padrão alvo` |
| `--maintain` | removido |
| relatório ao lado da entrada | `./artifacts` ou `--output-dir` |
| formato `json` | `jsonl` |
| JSON com `"contagem valor"` | arrays tipados `{value,count}` |
