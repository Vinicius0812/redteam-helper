# Contribuindo

Contribuições devem manter o foco em triagem defensiva, ensino e ambientes
explicitamente autorizados.

## Antes de enviar

1. Crie ou atualize uma fixture fictícia.
2. Adicione o resultado esperado ou uma asserção Bats específica.
3. Documente novos campos, opções e limitações.
4. Execute `bash scripts/check.sh`.
5. Confirme que nenhum log real, segredo, token ou dado pessoal foi incluído.

## Princípios de implementação

- mantenha Bash com `set -Eeuo pipefail`;
- quote expansões e separe opções de dados com `--`;
- prefira `jq` para JSON e `awk` para registros textuais;
- preserve as oito colunas do contrato normalizado;
- nunca inclua elevação de privilégio ou manutenção do host;
- não escreva na entrada;
- evite dependências ou camadas de abstração sem benefício demonstrado;
- trate regressão de parsing e mudança de schema como incompatibilidades.

## Ferramentas

Runtime: Bash 4.3+, jq 1.6+ e utilitários Unix usuais.

Desenvolvimento: ShellCheck 0.10+ e Bats 1.11+.

```bash
bash scripts/check.sh
```

## Commits e pull requests

Mantenha commits pequenos e descreva o comportamento alterado. No pull
request, informe os formatos afetados, testes adicionados e impacto no schema.
Use apenas dados reservados para documentação nas reproduções.
