# RedTeam Helper

Ferramenta Bash de triagem defensiva e reproduzível para logs de laboratórios,
CTFs e validações de segurança explicitamente autorizadas.

O nome do projeto preserva sua origem, mas a versão 0.2.0 tem foco em Blue
Team: normalizar registros, medir qualidade de parsing, destacar eventos de
interesse e produzir artefatos que possam ser comparados ou processados por
outras ferramentas.

> Use somente dados e sistemas próprios ou para os quais exista autorização
> explícita. A ferramenta não concede autorização para acessar ambientes de
> terceiros e os relatórios podem conter dados sensíveis.

## Principais recursos

- parsing de Apache Common/Combined, JSON Lines e syslog RFC3164/RFC5424;
- detecção automática ou seleção explícita do formato;
- entrada por arquivo, caminho relativo configurável ou stdin;
- rankings de IP, URL, User-Agent, status, método e volume por minuto;
- contagem de linhas processadas, inválidas e vazias;
- hunting sintático de flags, hashes, URLs, IPs e domínios;
- pesquisa regex ou literal em arquivos e diretórios;
- relatórios de texto, JSON estruturado e CSV;
- gravação atômica e recusa de sobrescrita sem `--force`;
- fixtures inteiramente fictícias, resultados esperados, Bats, ShellCheck e CI.

O RedTeam Helper não executa `sudo`, atualizações do sistema, exclusão de
evidências ou qualquer modificação do arquivo de entrada.

## Requisitos

Em execução:

- Bash 4.3 ou superior;
- `jq` 1.6 ou superior;
- utilitários usuais: `awk`, `grep`, `sed`, `sort`, `uniq`, `mktemp`, `date`,
  `basename`, `cat`, `cp`, `dirname`, `mkdir`, `mv` e `rm`.

Ubuntu/Debian:

```bash
sudo apt-get install bash jq gawk grep coreutils
```

Fedora:

```bash
sudo dnf install bash jq gawk grep coreutils
```

Arch Linux:

```bash
sudo pacman -S bash jq gawk grep coreutils
```

Os comandos privilegiados acima são somente exemplos opcionais de instalação
de dependências pelo operador; eles nunca são executados pela ferramenta.

A CI valida Ubuntu. Outras distribuições Linux devem funcionar quando os
requisitos estão presentes. Git Bash no Windows funciona com `jq.exe` no
`PATH`; WSL é recomendado para uma experiência Linux integral. macOS ainda é
considerado best-effort, pois as variações BSD de `grep`, `awk` e `mktemp` não
fazem parte da matriz atual de CI.

## Início rápido

```bash
git clone https://github.com/Vinicius0812/redteam-helper.git
cd redteam-helper
chmod +x redteam_helper.sh

./redteam_helper.sh --version
./redteam_helper.sh analyze fixtures/apache.log
./redteam_helper.sh hunt --output text,json,csv fixtures/hunt.txt
./redteam_helper.sh regex --ignore-case 'login|admin' fixtures/
```

Os artefatos são gravados em `./artifacts` por padrão:

```text
artifacts/
  apache.analysis.txt
  apache.analysis.json
  hunt.hunt.txt
  hunt.hunt.json
  hunt.hunt.csv
```

## Analisar logs

```bash
./redteam_helper.sh analyze [opções] <arquivo|->
```

Exemplos para situações diferentes:

```bash
# Detecção automática e relatórios text/JSON
./redteam_helper.sh analyze access.log

# Formato conhecido, CSV para planilha e 25 itens por ranking
./redteam_helper.sh analyze \
  --format apache \
  --top 25 \
  --output json,csv \
  --output-dir ./case-001 \
  /var/log/apache2/access.log

# Pipeline sem arquivo intermediário
journalctl -u nginx --no-pager | \
  ./redteam_helper.sh analyze --format syslog --input -

# Substitui artefatos anteriores de maneira explícita
./redteam_helper.sh analyze --force fixtures/events.jsonl
```

Formatos aceitos por `--format`: `auto`, `apache`, `jsonl` e `syslog`. A
detecção usa uma amostra de até 50 linhas não vazias e falha de forma segura
em empates ou quando não encontra evidência estrutural.

## Hunt de indicadores

```bash
./redteam_helper.sh hunt [opções] <arquivo|->
```

O comando extrai candidatos sintáticos e contabiliza ocorrências:

```bash
./redteam_helper.sh hunt \
  --top 50 \
  --output text,json,csv \
  --output-dir ./case-001 \
  mixed-events.log
```

Os resultados são pistas para triagem, não veredictos de comprometimento.
Endereços IPv4 e domínios são identificados por forma textual; confirme
validade, contexto, ownership e allowlists antes de responder a um incidente.

## Pesquisa regex

```bash
./redteam_helper.sh regex [opções] <padrão> <arquivo|diretório>
```

```bash
# Expressão regular estendida
./redteam_helper.sh regex '401|403|429' ./logs

# Texto literal iniciado por hífen
./redteam_helper.sh regex --fixed -- '-needle' fixtures/regex.txt

# Recursivo, sem diferenciar caixa, somente arquivos .log
./redteam_helper.sh regex --ignore-case --include '*.log' 'failed login' ./logs
```

O padrão é fornecido ao `grep` com `-e` e o alvo após `--`. Arquivos
binários são ignorados. Ausência de correspondências é um resultado válido e
retorna código zero; erros reais de leitura ou regex inválida retornam falha.

## Relatórios

O JSON usa `schema_version: "1.0"` e mantém valores e contagens separados:

```json
{
  "summary": {
    "total_lines": 6,
    "parsed_lines": 4,
    "invalid_lines": 1,
    "blank_lines": 1
  },
  "rankings": {
    "top_ips": [
      {"value": "192.0.2.10", "count": 2}
    ]
  }
}
```

- texto: resumo legível para revisão humana;
- JSON: métricas e rankings para automação;
- CSV de análise: eventos normalizados que foram processados;
- CSV de hunting: tipo, valor e quantidade de cada candidato.

Consulte [docs/FORMATS.md](docs/FORMATS.md) para o mapeamento de campos e
limitações e [docs/CLI.md](docs/CLI.md) para a referência completa da CLI.

## Segurança dos dados

- o arquivo de entrada é aberto somente para leitura;
- stdin é materializado em arquivo temporário privado ao processo;
- temporários são removidos por trap ao encerrar;
- cada artefato é criado temporariamente no diretório final e publicado com
  `mv` apenas depois de estar completo;
- arquivos existentes exigem `--force`;
- relatórios podem reproduzir IPs, URLs, User-Agents e IOCs presentes na fonte.

Trate `artifacts/` como evidência potencialmente sensível. A versão 0.2.0 não
anonimiza dados. Veja [SECURITY.md](SECURITY.md).

## Variável de ambiente

`REDTEAM_BASE_DIR` fornece um diretório base para entradas relativas que não
existam no diretório atual:

```bash
export REDTEAM_BASE_DIR="/srv/lab-logs"
./redteam_helper.sh analyze access.log
```

Entradas existentes no diretório atual e caminhos absolutos têm precedência.

## Códigos de saída

| Código | Significado |
| ---: | --- |
| 0 | sucesso, inclusive pesquisa sem correspondências |
| 2 | uso ou opção inválida |
| 3 | entrada ausente, ilegível ou erro de pesquisa |
| 4 | dependência ausente |
| 5 | formato desconhecido ou falha de parsing/serialização |
| 6 | falha ou conflito de saída |

## Desenvolvimento

Dependências adicionais: ShellCheck 0.10+ e Bats 1.11+.

```bash
bash scripts/check.sh
```

Esse comando executa sintaxe Bash, ShellCheck e 18 testes automatizados. As
fixtures usam somente endereços e domínios reservados para documentação. A
mesma verificação roda no GitHub Actions.

Estrutura:

```text
redteam_helper.sh          CLI e coordenação
lib/common.sh              validação, paths, temporários e saída atômica
lib/parsers.sh             detecção e normalização
lib/reports.sh             métricas, hunting e exportadores
fixtures/                  logs fictícios reproduzíveis
tests/                     testes Bats e resultados esperados
scripts/check.sh           gate local equivalente à CI
docs/                      documentação detalhada
```

A lista e o contrato de todas as funções internas estão em
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Para contribuir, consulte
[CONTRIBUTING.md](CONTRIBUTING.md).

## Limitações conhecidas

- não é um SIEM, correlacionador temporal ou motor Sigma;
- JSON de entrada deve ser JSON Lines, um objeto por linha;
- syslog é normalizado por cabeçalho e campos HTTP comuns, não por todos os
  formatos de mensagem de cada fornecedor;
- candidatos de hunting não recebem reputação ou enriquecimento externo;
- logs compactados precisam ser descompactados ou enviados por stdin;
- macOS ainda não faz parte da matriz de CI.

## Release

A versão declarada é `0.2.0`. O changelog está em [CHANGELOG.md](CHANGELOG.md)
e o procedimento demonstrável em [docs/RELEASE.md](docs/RELEASE.md).

## Licença

MIT. A licença permite uso e modificação do software, mas não substitui
autorização para acessar sistemas, logs ou dados de terceiros.
