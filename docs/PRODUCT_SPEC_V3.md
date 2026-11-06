# VULNRADAR V3 — AUDITORIA, CORREÇÃO E EVOLUÇÃO COMPLETA

## PAPEL

Atue simultaneamente como Principal Software Engineer, Software Architect, Senior Product Designer, AppSec Engineer, DevSecOps Engineer e QA Automation Engineer.

**Repositório:** https://github.com/Ivomsantiago/VulnRadar

Sua missão é revisar, corrigir, modernizar e completar o VulnRadar, utilizando o código existente como base. Não quero apenas sugestões, documentação ou modificações superficiais. Quero a implementação real das melhorias, com código funcional, testes e validação.

O VulnRadar deve evoluir para uma plataforma profissional de Vulnerability Intelligence, Application Security e Exposure Management, executável localmente e preparada arquiteturalmente para futuras integrações.

## 1. AUDITORIA COMPLETA DO PROJETO

Antes de alterar o código:

- Examine integralmente frontend, backend, banco de dados, APIs, serviços, workers, componentes, testes e configurações.
- Leia `AGENTS.md`, `README.md` e os documentos existentes em `docs/`.
- Identifique bugs, funcionalidades incompletas, problemas de desempenho, duplicações, falhas de segurança e inconsistências de interface.
- Verifique a integração real entre frontend e backend.
- Identifique botões que não funcionam, filtros ignorados, dados inconsistentes, endpoints quebrados e fluxos incompletos.
- Analise os tratamentos de erro, timeouts, reconexão, paginação, persistência e sincronização.
- Preserve funcionalidades existentes que estejam corretas.

Crie um plano objetivo de correção, priorizado por criticidade, mas não interrompa a execução para solicitar confirmação.

## 2. CORREÇÕES DO BACKEND

Revise principalmente:

- `backend/app/main.py`
- `backend/app/operations.py`
- `backend/app/services/scanner.py`
- `backend/app/services/intelligence.py`
- `backend/app/services/findings.py`
- `backend/app/services/monitoring.py`
- `backend/app/workers.py`
- `backend/app/security.py`

Implemente as correções necessárias:

1. Melhorar o desempenho do SCA, utilizando consultas OSV em lote quando adequado, cache, concorrência controlada e tratamento de rate limits.
2. Corrigir identificação e normalização de dependências diretas e transitivas.
3. Aprimorar os parsers de npm, Yarn, pnpm, Maven, Gradle, Python, Go, NuGet, Composer e demais ecossistemas suportados.
4. Impedir classificações incorretas de vulnerabilidades quando a versão não puder ser determinada.
5. Corrigir fingerprints SAST para evitar duplicações causadas apenas por deslocamentos de linhas.
6. Melhorar a identificação de achados persistentes, corrigidos e reabertos.
7. Garantir que análises parciais, canceladas ou com falhas nunca sejam consideradas resultados limpos.
8. Revisar a consistência de transações, migrações, estados dos workers e execução de tarefas.
9. Melhorar observabilidade, diagnóstico de falhas e registros técnicos sem expor informações sensíveis.
10. Implementar testes de regressão para cada correção.

Não apresente correspondência SCA como prova de explorabilidade e não invente versões corrigidas.

## 3. INTELIGÊNCIA DE VULNERABILIDADES

Melhore as integrações existentes:

- NVD
- GitHub Security Advisories
- OSV
- CISA KEV
- FIRST EPSS

Implemente:

- Monitoramento contínuo e incremental de novas CVEs.
- Detecção de alterações em vulnerabilidades já registradas.
- Correlação de CVE, GHSA, aliases e pacotes afetados.
- Histórico de modificações, severidade e exploração conhecida.
- Comparação entre versões afetadas e corrigidas.
- Filtros por ecossistema, fornecedor, produto, versão, severidade, EPSS, KEV e período.
- Monitoramento de tecnologias e versões específicas.
- Alertas de vulnerabilidades relevantes aos repositórios cadastrados.
- Identificação de informações ausentes, conflitantes ou não verificadas.
- Diferenciação entre nova publicação, atualização de advisory e descoberta local.

Toda informação exibida deve indicar sua fonte e, quando disponível, a data da última atualização.

Não chame uma vulnerabilidade de zero-day sem evidência adequada. Não interprete ausência no KEV como ausência de exploração.

## 4. ANÁLISE DE REPOSITÓRIOS

Reestruture e melhore o fluxo completo:

Cadastro → Inspeção → Seleção do mecanismo → Análise → Resultados → Investigação → Remediação → Reanálise.

Funcionalidades necessárias:

- Selecionar repositórios locais dentro das raízes autorizadas.
- Detectar linguagens, frameworks, manifestos e lockfiles.
- Analisar dependências SCA.
- Executar análise SAST.
- Permitir análise combinada.
- Exibir andamento real por etapa.
- Cancelar análises com segurança.
- Mostrar resultados estruturados e pesquisáveis.
- Comparar execuções anteriores.
- Identificar vulnerabilidades novas, persistentes, corrigidas e recorrentes.
- Preservar histórico e evidências.
- Exibir arquivos e linhas afetadas.
- Apresentar recomendações de correção baseadas em evidências.
- Informar quando o mecanismo utilizado não oferecer cobertura suficiente.

Adicione integração opcional com Trivy e Grype para análise de imagens OCI e dependências de sistema operacional, sem prejudicar o funcionamento quando esses mecanismos não estiverem instalados.

Mantenha isolamento e limites de recursos. Não execute scripts, builds ou instaladores arbitrários de repositórios analisados.

## 5. GESTÃO DE VULNERABILIDADES E REMEDIAÇÃO

Transforme a triagem existente em um fluxo operacional completo.

Cada achado deverá permitir:

- Identificação única e estável.
- Projeto e componente afetado.
- Severidade e prioridade justificadas.
- Versão instalada e correção disponível.
- Evidências técnicas.
- Histórico das detecções.
- Classificação de aplicabilidade.
- Registro de falso positivo com justificativa.
- Aceite de risco com justificativa e validade.
- Atribuição de responsável.
- Definição de prazo e SLA.
- Registro de plano de correção.
- Histórico auditável de alterações.
- Reabertura quando o problema for detectado novamente.
- Comparação de resultados antes e depois da correção.

Não encerrar automaticamente achados somente porque desapareceram de uma análise parcial.

## 6. REDESIGN COMPLETO DO FRONTEND

Revise toda a interface React/TypeScript.

Arquivos principais:

- `frontend/src/main.tsx`
- `frontend/src/Overview.tsx`
- `frontend/src/Investigation.tsx`
- `frontend/src/Findings.tsx`
- `frontend/src/Projects.tsx`
- `frontend/src/Search.tsx`
- `frontend/src/Watchlist.tsx`
- `frontend/src/Reports.tsx`
- `frontend/src/Settings.tsx`
- `frontend/src/ui.tsx`
- `frontend/src/style.css`

Quero uma interface moderna, consistente, sofisticada e funcional, inspirada na qualidade de UX de Linear, Wiz, Snyk, Datadog e Vercel, sem copiar literalmente nenhuma delas.

### Diretrizes visuais

- Design premium, minimalista e profissional.
- Tema escuro como padrão, com tema claro completo.
- Tipografia legível e hierarquia visual clara.
- Eliminar fontes excessivamente pequenas.
- Padronizar cores, espaços, bordas e tamanhos.
- Melhorar alinhamentos, densidade de tabelas e distribuição dos componentes.
- Utilizar cores de severidade apenas onde houver significado.
- Evitar cartões decorativos, gráficos inúteis e excesso de informações.
- Implementar tabelas com ordenação, filtros, paginação e ações contextuais.
- Utilizar skeletons, empty states, mensagens de erro e confirmação.
- Garantir acessibilidade por teclado e design responsivo.
- Evitar excesso de modais e telas que obriguem o usuário a navegar desnecessariamente.

Crie componentes reutilizáveis, mantendo o projeto sustentável.

### Dashboard

Reorganize o dashboard para apresentar, por ordem de importância:

1. Exposição real dos projetos cadastrados.
2. Vulnerabilidades críticas e altas abertas.
3. Vulnerabilidades com exploração conhecida.
4. Prioridades de investigação.
5. Cobertura e saúde das análises.
6. Novas vulnerabilidades relevantes.
7. Evolução de achados e remediações.
8. Inteligência global, claramente separada da exposição local.

Os indicadores devem ser clicáveis e abrir visualizações já filtradas.

Quando não houver dados suficientes, exiba estado desconhecido ou não analisado, nunca zero artificial.

### Navegação

Reduza a complexidade da sidebar, consolidando páginas redundantes e organizando o produto por jornadas:

- Visão geral
- Inteligência de vulnerabilidades
- Aplicações e repositórios
- Análises e inventário
- Investigação e remediação
- Monitoramento e alertas
- Relatórios
- Configurações

Preserve compatibilidade com URLs antigas.

### Investigação

Crie uma experiência de investigação clara, com:

- Resumo técnico.
- Dados de severidade.
- Evidências e referências.
- Componentes afetados.
- Versões vulneráveis e corrigidas.
- Repositórios relacionados.
- Histórico.
- Triagem e ações de remediação.

O analista deve conseguir entender o problema e tomar uma decisão sem abrir inúmeras páginas.

## 7. RELATÓRIOS

A página atual de relatórios deve ser ampliada.

Implemente relatórios:

- Por repositório.
- Por período.
- Por severidade.
- Por status de remediação.
- Por tecnologia.
- Por tipo de análise.
- De vulnerabilidades novas e corrigidas.
- De evolução da exposição.
- De cobertura de análise.
- De SLAs e pendências.

Permita exportações técnicas em JSON, CSV, SARIF e CycloneDX quando aplicável, além de relatórios PDF bem formatados.

Não use números fictícios.

## 8. SEGURANÇA DA PRÓPRIA FERRAMENTA

Realize revisão AppSec do VulnRadar.

Verifique e corrija, conforme necessário:

- Path traversal.
- Symlinks e junctions.
- Condições de corrida em leitura de arquivos.
- SSRF em webhooks e integrações.
- XSS e renderização de dados externos.
- Exposição de credenciais.
- Injeção de comandos.
- Controle de acesso ao filesystem.
- Consumo excessivo de memória e CPU.
- Timeouts e processos órfãos.
- CORS e políticas de segurança HTTP.
- Logs contendo informações sensíveis.
- Dependências vulneráveis.
- Riscos do armazenamento local.

Preserve o modelo local por padrão. Não exponha a API publicamente sem autenticação, autorização e isolamento adequados.

## 9. QUALIDADE E TESTES

Execute e ajuste:

- Testes unitários de backend.
- Testes unitários de frontend.
- Testes de integração.
- Testes dos parsers SCA.
- Testes dos mecanismos SAST.
- Testes das APIs.
- Testes de migração e preservação de dados.
- Testes de cancelamento e falhas parciais.
- Testes ponta a ponta com Playwright.
- Testes de responsividade.
- Testes automatizados de acessibilidade.
- Verificação de build.
- Verificação de dependências.

Teste as jornadas reais: cadastrar projeto, executar análise, consultar achado, registrar FP, registrar remediação e reanalisar.

Utilize banco descartável para testes. Não modifique ou apague dados operacionais.

## 10. REGRAS DE IMPLEMENTAÇÃO

- Não reescrever todo o projeto sem necessidade.
- Não remover funcionalidades existentes para simplificar o trabalho.
- Não substituir recursos funcionais por mocks.
- Não criar botões sem ações implementadas.
- Não declarar recursos completos sem testes.
- Não adicionar dependências desnecessárias.
- Não introduzir alterações destrutivas de banco.
- Não inserir segredos no código.
- Não mascarar erros com mensagens de sucesso.
- Não deixar código temporário ou placeholders como entrega final.
- Não realizar push, merge ou publicação sem autorização.

Trabalhe em etapas coerentes e mantenha o código funcional após cada etapa.

Quando algum requisito não puder ser concluído, documente a limitação com precisão, sem simular sua implementação.

## 11. CRITÉRIOS DE ACEITE

A implementação será considerada concluída quando:

1. Frontend e backend iniciarem corretamente.
2. A navegação e as ações principais funcionarem.
3. O dashboard apresentar métricas consistentes.
4. A coleta das fontes e o monitoramento funcionarem conforme sua cobertura documentada.
5. O SCA identificar componentes, versões e advisories corretamente nos cenários testados.
6. O SAST produzir achados rastreáveis.
7. O sistema preservar evidências e histórico.
8. A triagem e remediação persistirem corretamente.
9. Não houver regressões conhecidas nos fluxos existentes.
10. Os testes exigidos passarem ou as falhas remanescentes estiverem explicitamente documentadas.
11. O design estiver consistente nas principais resoluções.
12. A documentação corresponder ao comportamento real da aplicação.

## ENTREGA FINAL

Ao terminar, apresente:

- Arquivos modificados.
- Problemas corrigidos.
- Funcionalidades implementadas.
- Melhorias de UX/UI.
- Decisões arquiteturais importantes.
- Testes executados e seus resultados.
- Limitações remanescentes.
- Instruções para execução local.

**Comece pela auditoria do código existente e avance imediatamente para as correções e implementações. O objetivo é entregar software funcional e validado, não apenas um relatório de recomendações.**
