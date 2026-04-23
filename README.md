# Red Team Helper

Script Bash para CTF e triagem de logs em ambiente Kali.

## O que ele faz

- Executa manutencao do Kali (`apt update` + `dist-upgrade`)
- Analisa logs (`apache`, `json`, `syslog`) com extração de:
  - top IP
  - top URL
  - top User-Agent
  - top status code
  - top metodo HTTP
  - pico de requisicoes por minuto
- Faz IOC/Flag hunting:
  - flags (`flag{...}`, `ctf{...}`)
  - hashes (MD5/SHA1/SHA256)
  - URLs, IPs e dominios
- Filtro regex em `.txt` (arquivo ou diretorio recursivo)

## Requisitos

- Bash
- `awk`, `grep`, `sort`, `uniq`, `sed`, `date`, `mktemp`
## Uso

```bash
./redteam_helper.sh --help
./redteam_helper.sh --analyze logs.txt
./redteam_helper.sh --hunt logs.txt
./redteam_helper.sh --regex 'flag\{.*\}' .
```

## Variavel de ambiente

```bash
export REDTEAM_BASE_DIR="/home/vinicius/logs"
```

Com isso, arquivos relativos como `logs.txt` serao resolvidos automaticamente nesse caminho.

## Estrutura

```text
redteam-helper/
  redteam_helper.sh
  README.md
  LICENSE
  .gitignore
```
