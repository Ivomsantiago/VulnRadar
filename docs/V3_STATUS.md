# V3: correções implementadas e limites

Base main b075aab. Migração 0005 aditiva, sem remoção de dados. Esta entrega cobre correções centrais e expansão de remediação/relatórios; **não representa conclusão integral de todos os requisitos V3**.

## Implementado
- Fingerprint SAST por regra/arquivo/conteúdo e ordinal para ocorrências iguais; mudanças de linha não criam novos achados. Migração conservadora da identidade legada somente com evidência inequívoca.
- Correções SCA restritas ao pacote/ecossistema correspondente; não mistura versões corrigidas de outros componentes do advisory.
- Classificação direta/transitiva npm baseada no caminho real de instalação e incluindo dev/optional; pnpm usa referências dos importers quando disponíveis.
- POM usa dependências do projeto, não dependencyManagement como inventário instalado; propriedades locais resolvidas, cobertura residual explicitada. Marcadores Python produzem aviso de cobertura, não resultado limpo.
- Manifestos lidos com limite e O_NOFOLLOW na folha em plataformas compatíveis. Corridas nos diretórios ancestrais continuam exigindo árvore confiável/isolamento.
- SCA com quatro consultas simultâneas, tarefas em lotes de 40 e deduplicação por identidade/versão. Cache OSV de sucesso por 5 minutos, máximo 256 entradas, cópias independentes; falhas não são cacheadas. Paginação repetida é rejeitada como consulta incompleta.
- Histórico de alterações de advisory inclui classificação/CVSS/data anterior e atual.
- Responsável, prazo, plano de correção e validade do risco persistidos. Aceite sem validade futura rejeitado. Aceite expirado reabre quando o achado reaparece; FP justificado permanece preservado.
- Relatórios por projeto, primeira observação/período, severidade, estado, tecnologia e motor, com prazo vencido e cobertura de execuções. Preview e exportação usam a mesma consulta; até 5000 linhas com truncamento explícito.
- CSV protegido contra fórmulas, JSON, e impressão formatada para salvar PDF no navegador. SARIF/CycloneDX permanecem por execução; não há endpoint de geração PDF servidor.
- Metadados/fontes de tabela ampliados para legibilidade; estilos de impressão removem controles e navegação.

## Validação

- Backend: 72 testes aprovados, incluindo 5 integrações externas reais. 67 locais + 5 opcionais.
- Frontend: 7 testes aprovados, TypeScript e build aprovados.
- Semgrep real confirma que deslocamento de três linhas preserva o digest de código.
- Regressões cobrem duplicação de ocorrências, correções de pacote, concorrência/cache, classificação npm, validade do risco, responsável, relatório/CSV, normalização de fusos horários, cancelamento persistido e preservação de achados/evidências durante a migração 0004 → 0005.
- Navegador V3: 11 cenários aprovados, incluindo FP com responsável, relatório filtrado, geração PDF por Chromium, WCAG automatizado e 17 rotas em seis larguras. A fixture OSV é explicitamente fictícia nesta suíte; Semgrep é real. Testes usam banco descartável.

## Ainda pendente da especificação V3

- Trivy/Grype e análise OCI não foram integrados; não existe botão que simule esse suporte. É necessário modelar achados de sistema/container separadamente e validar instalação/execução dos binários.
- Filtros CPE/fornecedor/produto/versões de runtime ainda precisam de modelo estruturado e semântica de intervalos por ecossistema.
- Não foi substituída a navegação V2 inteira pelas oito jornadas V3; rotas existentes foram preservadas.
- Relatórios usam estado atual e primeira observação, não reconstrução histórica completa de exposição. Não calcular tendências/SLA fictícios. PDF depende do recurso de impressão do navegador.
- Não há queries OSV batch remotas; esta entrega usa concorrência limitada e cache com a API paginada existente.
- Variantes históricas de lockfiles, resolução remota Maven/Gradle, análise de ambiente Python e alcance transitivo completo continuam limitados.
- Não há garantia de remoção de corridas em árvores adversariais, sandbox forte, implantação multiusuário ou certificação WCAG. Permanecem as limitações V2 em IMPLEMENTATION_STATUS.md.

Execução: `bash scripts/install.sh` atualiza dependências/build/migrações; `bash scripts/start.sh` inicia localmente. Preserve backup antes da migração de banco operacional. Navegador: servidor descartável `scripts/start_test_server.py --mock-osv`, depois Playwright. Não publicar ambiente, merge ou release automaticamente.

Falhas intermediárias corrigidas: formulário não enviava atribuição; labels de filtros de relatório eram ambíguos; links em alertas dependiam só de cor. SARIF foi verificado com dez respostas HTTP 200; o teste permite uma única repetição de conexão ECONNRESET, sem ignorar erros HTTP ou asserções.

Atualização local validada: backup SQLite consistente em diretório privado antes da migração; todos os registros e campos anteriores preservados em 15 tabelas, integridade SQLite aprovada, esquema 0005. Nenhum dado de fixture foi inserido no banco operacional.
