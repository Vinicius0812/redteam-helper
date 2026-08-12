# Referência da CLI

## Convenções

- `<arquivo|->`: caminho de arquivo ou `-` para stdin;
- `<lista>`: valores separados por vírgula e sem espaços;
- mensagens informativas e erros são escritos no stderr;
- resultados do comando `regex` são escritos no stdout;
- artefatos são escritos somente no diretório de saída.

## Comandos globais

```bash
./redteam_helper.sh --help
./redteam_helper.sh --version
./redteam_helper.sh menu
```

Sem argumentos, a ferramenta mostra ajuda e termina. O menu precisa de um TTY
interativo e oferece apenas `analyze`, `hunt`, `regex`, ajuda e saída.

Os aliases antigos `--analyze`, `--hunt` e `--regex` permanecem disponíveis.
`--maintain` foi removido na 0.2.0 porque manutenção privilegiada do sistema não
pertence ao escopo de triagem.

## `analyze`

```text
redteam_helper.sh analyze [opções] <arquivo|->
```

| Opção | Padrão | Descrição |
| --- | --- | --- |
| `--input <arquivo|->` | posicional | Define explicitamente a entrada. |
| `--format <formato>` | `auto` | `auto`, `apache`, `jsonl` ou `syslog`. |
| `--output-dir <dir>` | `./artifacts` | Diretório dos relatórios. |
| `--output <lista>` | `text,json` | Um ou mais de `text`, `json`, `csv`. |
| `--top <n>` | `10` | Quantidade máxima em cada ranking. |
| `--force` | desativado | Autoriza substituição atômica de artefatos. |
| `--quiet` | desativado | Oculta mensagens `[INFO]`. |
| `-h`, `--help` | — | Mostra ajuda do comando. |

O nome do artefato deriva do basename da entrada. `access.log` produz
`access.analysis.json`; stdin produz `stdin.analysis.json`. Caracteres fora de
`A-Za-z0-9._-` são trocados por `_`.

O CSV de análise contém apenas registros processados, com as colunas:

```text
ip,url,user_agent,status,method,minute
```

As contagens de registros inválidos e vazios permanecem no JSON e no texto.

## `hunt`

```text
redteam_helper.sh hunt [opções] <arquivo|->
```

| Opção | Padrão | Descrição |
| --- | --- | --- |
| `--input <arquivo|->` | posicional | Define explicitamente a entrada. |
| `--output-dir <dir>` | `./artifacts` | Diretório dos relatórios. |
| `--output <lista>` | `text,json` | Um ou mais de `text`, `json`, `csv`. |
| `--top <n>` | `20` | Limite por tipo de indicador. |
| `--force` | desativado | Autoriza substituição atômica. |
| `--quiet` | desativado | Oculta mensagens `[INFO]`. |
| `-h`, `--help` | — | Mostra ajuda do comando. |

Tipos extraídos:

- `flag`: formas `flag{...}` e `ctf{...}`;
- `hash`: sequências hexadecimais de 32, 40 ou 64 caracteres;
- `url`: strings iniciadas por `http://` ou `https://`;
- `ip`: candidatos com quatro octetos decimais;
- `domain`: nomes DNS textuais.

O CSV possui `type,value,count`. O hunting é deliberadamente offline: não faz
DNS, WHOIS, consulta de reputação nem envio de indicadores a terceiros.

## `regex`

```text
redteam_helper.sh regex [opções] <padrão> <arquivo|diretório>
```

| Opção | Padrão | Descrição |
| --- | --- | --- |
| `--fixed` | regex ERE | Usa busca literal (`grep -F`). |
| `--ignore-case` | diferencia caixa | Usa busca case-insensitive. |
| `--include <glob>` | `*` | Limita nomes em busca recursiva. |
| `-h`, `--help` | — | Mostra ajuda do comando. |

Em arquivo, o resultado usa `linha:conteúdo`. Em diretório, usa
`arquivo:linha:conteúdo`. Binários são ignorados. Um padrão iniciado por hífen
pode ser separado das opções com `--`.

## Resolução da entrada

Para entradas diferentes de stdin:

1. caminho absoluto ou caminho existente no diretório atual;
2. `REDTEAM_BASE_DIR/<entrada>`, quando a variável estiver definida;
3. caminho original, que produzirá erro de entrada caso não exista.

## Códigos de saída

| Código | Categoria |
| ---: | --- |
| 0 | sucesso |
| 2 | uso inválido |
| 3 | entrada ou pesquisa |
| 4 | dependência |
| 5 | formato, parsing ou serialização |
| 6 | saída |

Esses códigos permitem uso previsível em pipelines e CI.
