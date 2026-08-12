# Changelog

As mudanças relevantes deste projeto são documentadas aqui.

## [0.2.0] - 2026-08-12

### Adicionado

- CLI por comandos `analyze`, `hunt`, `regex` e `menu`;
- entrada por stdin, `--format`, `--output-dir`, `--output`, `--top`, `--quiet`
  e `--force`;
- parsing real de JSON Lines com `jq` e aliases ECS comuns;
- suporte separado a Apache Common/Combined e syslog RFC3164/RFC5424;
- contagens de qualidade de parsing e endpoints de interesse defensivo;
- relatórios estruturados JSON schema 1.0 e CSV;
- escrita atômica e proteção contra sobrescrita;
- fixtures fictícias e resultados esperados;
- 18 testes Bats, ShellCheck, verificação de sintaxe e GitHub Actions;
- documentação completa de CLI, formatos, arquitetura e segurança.

### Alterado

- reposicionamento do projeto para triagem defensiva autorizada;
- modularização em `common.sh`, `parsers.sh` e `reports.sh`;
- relatórios deixam de codificar valor e contagem na mesma string;
- formato `json` passa a se chamar `jsonl` na seleção da CLI.

### Removido

- manutenção do Kali, `sudo apt update` e `dist-upgrade`;
- escrita de relatórios ao lado do arquivo de evidência por padrão;
- construção manual e frágil de JSON.

### Segurança

- regex fornecida com `grep -e` e caminhos separados por `--`;
- temporários limpos somente pelo processo Bash principal;
- entrada protegida por testes de imutabilidade.

## [0.1.0]

- script inicial para CTF, análise de logs, hunting e regex.
