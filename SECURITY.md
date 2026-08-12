# Política de segurança e uso autorizado

## Escopo de uso

O RedTeam Helper é destinado a:

- laboratórios próprios;
- CTFs e desafios nos quais a análise seja permitida;
- triagem de logs que o operador esteja autorizado a acessar;
- validação defensiva com escopo e consentimento explícitos.

Não use a ferramenta para acessar, copiar ou analisar dados de terceiros sem
autorização. A licença do código não concede permissão sobre sistemas ou dados.

## Modelo operacional

A ferramenta:

- não exige root nem executa `sudo`;
- não modifica o arquivo de entrada;
- não faz conexões de rede ou enriquecimento externo;
- escreve somente temporários e artefatos no destino escolhido;
- exige `--force` para substituir um artefato existente.

Os relatórios podem conter cópias de dados sensíveis presentes nos logs.
Aplique controles de acesso, retenção e descarte compatíveis com o ambiente.
Evite publicar artefatos reais em issues ou pull requests.

## Reportar vulnerabilidades

Não publique detalhes exploráveis ou dados sensíveis em uma issue aberta.
Prefira um Security Advisory privado do GitHub para o repositório. Inclua:

- versão e ambiente;
- comando mínimo para reprodução;
- impacto observado;
- fixture fictícia, nunca logs reais;
- correção sugerida, quando disponível.

## Premissas e limites

Entradas são consideradas potencialmente hostis. Quoting, `grep -e`, `--` e
serialização por `jq` reduzem riscos de injeção, mas o processamento ainda pode
consumir CPU e disco proporcionalmente ao volume. Use limites de recursos ao
analisar amostras não confiáveis ou muito grandes.

Os indicadores extraídos não representam confirmação de incidente. Valide o
contexto antes de bloquear, isolar ou escalar qualquer ativo.
