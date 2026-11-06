# VULN RADAR — MASTER SPECIFICATION V2
## Plataforma profissional de Application Security, Vulnerability Intelligence e Exposure Management

### MISSÃO PRINCIPAL

Atue como um **Principal Software Architect, Staff Frontend Engineer, Principal Product Designer, AppSec Engineer e Threat Intelligence Specialist**.

Sua responsabilidade é desenvolver, revisar e aprimorar integralmente o **Vuln Radar**, transformando-o em uma plataforma profissional de segurança de aplicações, com arquitetura robusta, inteligência de vulnerabilidades, análise de repositórios e uma interface excepcionalmente bem organizada.

**Não quero um dashboard genérico com cards, gráficos e tabelas. Quero um produto de segurança que permita investigar, contextualizar, priorizar e acompanhar vulnerabilidades de forma rápida, precisa e operacional.**

Utilize como referências de qualidade e experiência de produto:

- Linear — clareza, navegação e organização.
- Wiz — gestão de exposição e contextualização de riscos.
- Snyk — experiência de investigação de vulnerabilidades e dependências.
- Datadog — dashboards, filtros e exploração de dados.
- CrowdStrike — fluxos operacionais de investigação.
- Vercel — consistência visual, tipografia e simplicidade.

Não reproduza suas interfaces literalmente. Desenvolva identidade própria para o Vuln Radar.

## 1. PRINCÍPIOS OBRIGATÓRIOS

A interface deve respeitar cinco princípios:

**1. Informação antes de decoração.** Cada componente precisa ter uma finalidade operacional.

**2. Priorização antes de volume.** Milhares de CVEs não ajudam se o analista não conseguir identificar quais afetam suas aplicações.

**3. Contexto antes de classificação.** Uma CVE crítica publicada não significa que um repositório esteja vulnerável.

**4. Investigação antes de navegação excessiva.** O usuário deve acessar evidências, versões, correções e projetos relacionados com poucos cliques.

**5. Consistência antes de complexidade.** Todas as páginas devem seguir os mesmos padrões visuais e comportamentais.

O projeto deve ser implementado integralmente, testado e preparado para publicação no GitHub.

---

# 2. REORGANIZAÇÃO COMPLETA DA NAVEGAÇÃO

A arquitetura atual de navegação precisa ser revista.

Crie uma estrutura clara, com agrupamentos funcionais:

### OVERVIEW
- Dashboard
- Central de prioridades

### VULNERABILITY INTELLIGENCE
- Feed de vulnerabilidades
- Busca avançada
- Tecnologias e bibliotecas
- Exploração conhecida

### APPLICATION SECURITY
- Repositórios
- Análises SCA
- Análises SAST
- Inventário de componentes / SBOM

### GESTÃO
- Watchlist
- Alertas
- Triagem e remediação
- Relatórios

### PLATAFORMA
- Fontes de inteligência
- Histórico e jobs
- Configurações

A navegação lateral deverá ser recolhível e apresentar ícones consistentes, estados ativos, contadores úteis e organização visual clara.

Evite menus excessivamente longos. Se necessário, use grupos expansíveis.

A topbar deve disponibilizar pesquisa universal, estado de sincronização, notificações e acesso às configurações.

Preserve rotas antigas por meio de redirecionamentos quando necessário.

---

# 3. DESIGN SYSTEM — IDENTIDADE VISUAL PREMIUM

Desenvolva um design system próprio, moderno e sofisticado.

### Direção visual

A interface deve transmitir:

- Precisão.
- Confiabilidade.
- Clareza.
- Tecnologia.
- Organização.
- Profissionalismo.

Não use estética de painel administrativo genérico.

### Paleta de referência

Adote inicialmente tokens semelhantes aos seguintes, ajustando contraste e acessibilidade:

| Elemento | Referência |
|---|---|
| Fundo principal | #090D16 |
| Sidebar | #0D1320 |
| Superfície de cards | #121B2B |
| Superfície elevada | #192539 |
| Bordas | #263449 |
| Texto principal | #F1F5F9 |
| Texto secundário | #94A3B8 |
| Cor de destaque | #38BDF8 |
| Sucesso | #34D399 |
| Atenção | #FBBF24 |
| Crítico | #FB7185 |

Utilize variáveis de tema, não valores espalhados pelos componentes.

As cores de severidade devem obedecer a um padrão consistente, sem transformar toda a interface em um ambiente vermelho e laranja.

### Tipografia

Utilize Inter, Geist ou equivalente profissional, conforme licença e disponibilidade.

Defina claramente:

- Títulos de páginas.
- Títulos de seções.
- Números de indicadores.
- Texto de tabelas.
- Metadados.
- Rótulos.
- Estados e avisos.

Evite sombras excessivas, textos com contornos e títulos desproporcionais.

Use números tabulares para métricas e pontuações.

### Componentes

Crie componentes reutilizáveis para:

- KPI cards.
- Tabelas.
- Gráficos.
- Filtros.
- Search inputs.
- Drawers.
- Dialogs.
- Tabs.
- Badges.
- Tooltips.
- Notifications.
- Status indicators.
- Empty states.
- Loading skeletons.
- Progress indicators.
- Pagination.
- Breadcrumbs.

A interface deve parecer parte de um único produto, não um conjunto de telas desenvolvidas separadamente.

---

# 4. DASHBOARD — REDESIGN E REORGANIZAÇÃO DAS INFORMAÇÕES

A tela inicial deve ser reconstruída como um **centro de operações de segurança de aplicações**.

Organize-a em camadas.

## CAMADA 1 — VISÃO EXECUTIVA

No topo, exiba quatro indicadores principais:

1. Vulnerabilidades relevantes para projetos monitorados.
2. Achados críticos e altos ainda abertos.
3. Vulnerabilidades com exploração conhecida relacionadas aos ativos.
4. Novas vulnerabilidades relevantes nas últimas 24 horas.

Cada card deve ter:

- Valor principal.
- Contexto.
- Variação temporal, quando calculável.
- Período.
- Estado da informação.
- Ação de navegação.

Se não houver repositórios cadastrados, apresente um estado inicial adequado. Não substitua esses indicadores por contagens globais de CVEs sem informar a diferença.

## CAMADA 2 — THREAT INTELLIGENCE GLOBAL

Apresente em uma seção independente:

- Novas CVEs publicadas.
- CVEs críticas e altas.
- Novas entradas KEV.
- Tendência de divulgações.
- Tecnologias mais citadas nas fontes coletadas.

Distinguir explicitamente:

**Inteligência global:** vulnerabilidades divulgadas publicamente.

**Exposição das aplicações:** correspondências verificadas com inventários dos repositórios.

Esses dois conceitos não devem ser misturados nos mesmos indicadores.

## CAMADA 3 — PRIORIZAÇÃO OPERACIONAL

Criar uma tabela chamada **Vulnerabilidades que exigem atenção**.

Colunas:

- CVE/GHSA.
- Componente.
- Projeto afetado.
- Versão instalada.
- CVSS.
- EPSS.
- KEV.
- Prioridade.
- Status.

A tabela deve se basear nos achados efetivos e nas evidências disponíveis.

Permitir abrir diretamente a investigação.

## CAMADA 4 — GRÁFICOS

Implementar visualizações úteis:

- Publicações por dia.
- Novas vulnerabilidades por severidade.
- Distribuição de CVSS.
- Distribuição de EPSS.
- Tecnologias com mais advisories.
- Evolução de achados abertos e resolvidos.

Evite repetir o mesmo dado em múltiplos gráficos.

Permita selecionar 7, 30, 60 e 90 dias quando houver histórico suficiente.

## CAMADA 5 — ATIVIDADE RECENTE

Exibir:

- Novas CVEs relevantes.
- Entradas adicionadas ao KEV.
- Atualizações de advisories.
- Scans concluídos.
- Novos achados.
- Alterações de triagem.

Usar uma timeline compacta, com data, tipo de evento e referência.

---

# 5. FEED DE VULNERABILIDADES — NOVA EXPERIÊNCIA

A tela atual desperdiça muito espaço com filtros distribuídos em diversas linhas.

Reconstrua-a com uma organização operacional.

### Cabeçalho

Título: Vulnerability Intelligence

Subtítulo curto que explique o escopo dos resultados.

Apresentar:

- Total de resultados.
- Última sincronização.
- Fontes consultadas.
- Botão de atualização.

### Barra de ações

Adicionar uma busca textual principal e filtros rápidos:

- Todas.
- Críticas.
- Altas.
- KEV.
- Novas.
- Atualizadas.

Adicionar botão **Filtros avançados**, abrindo drawer lateral.

### Filtros avançados

Organizar por grupos:

**Classificação**
- Severidade.
- CVSS.
- EPSS.
- KEV.

**Tecnologia**
- Linguagem.
- Ecossistema.
- Biblioteca.
- Produto.

**Temporalidade**
- Publicação.
- Atualização.
- Intervalo personalizado.

**Investigação**
- Fonte.
- Estado de triagem.
- Projetos relacionados.

Permitir combinar filtros, limpar todos e salvar filtros favoritos.

Mostrar chips dos filtros ativos.

### Tabela principal

Priorize legibilidade.

Exiba inicialmente:

- Identificador.
- Descrição resumida.
- Componente.
- Severidade.
- CVSS.
- EPSS.
- KEV.
- Publicação.
- Status.

Mova metadados menos importantes para detalhes ou configurações de colunas.

Implemente:

- Colunas configuráveis.
- Ordenação.
- Paginação server-side.
- Densidade compacta ou confortável.
- Seleção de registros.
- Tooltips.
- Estados vazios.
- Indicadores de atualização.

### Investigação de CVE

Ao selecionar uma linha, abra um drawer de detalhes ocupando espaço adequado.

Organize em abas:

**Resumo**
- Descrição.
- Severidade.
- CVSS.
- EPSS.
- KEV.
- CWE.

**Componentes afetados**
- Ecossistemas.
- Pacotes.
- Versões vulneráveis.
- Versões corrigidas.

**Exploração**
- Evidências.
- Referências.
- Pré-condições documentadas.
- Status de exploração conhecida.

**Projetos relacionados**
- Aplicações.
- Versões encontradas.
- Análises.
- Status de correção.

**Histórico**
- Publicação.
- Atualizações.
- Alterações de classificação.
- Eventos de triagem.

Não misturar dados ausentes com resultados negativos.

---

# 6. BUSCA UNIVERSAL — INVESTIGAÇÃO SEM FRICÇÃO

A busca deve ser uma ferramenta central do produto.

Implementar comportamento semelhante a uma command palette.

Atalho de teclado: Ctrl+K.

Aceitar:

- CVE.
- GHSA.
- OSV ID.
- Biblioteca.
- Framework.
- Runtime.
- Tecnologia.
- Repositório.
- Pacote e versão.

Apresentar resultados por categoria.

### Busca de pacotes

Criar uma tela com apenas os controles essenciais:

- Ecossistema.
- Nome do pacote.
- Versão opcional.
- Consultar.

Abaixo, exibir os resultados completos.

Não manter grandes caixas vazias contendo apenas instruções.

### Resultado da avaliação

Exibir:

- Componente pesquisado.
- Versão consultada.
- Estado da consulta.
- Quantidade de advisories correspondentes.
- CVEs/GHSAs.
- Severidade.
- Versões afetadas.
- Correções.
- Referências.

Distinguir:

- Versão afetada segundo advisory.
- Nenhuma correspondência encontrada nas fontes consultadas.
- Consulta incompleta.
- Versão não identificada.
- Pacote não suportado.

Não transformar ausência de resultados em confirmação de segurança.

---

# 7. ANÁLISE DE REPOSITÓRIOS — EXPERIÊNCIA DE PRODUTO

A experiência atual expõe configurações técnicas como `--scan-root` e variáveis do Semgrep diretamente ao usuário, além de apresentar um fluxo pouco intuitivo.

Transforme essa página em uma central de análise.

### Etapa 1 — Cadastrar repositório

Permitir selecionar uma pasta local dentro das raízes autorizadas pelo servidor.

Mostrar:

- Nome do projeto.
- Caminho validado.
- Linguagens detectadas.
- Lockfiles encontrados.
- Frameworks identificados.

Se a seleção estiver indisponível, oferecer instruções práticas de configuração.

### Etapa 2 — Escolher análise

Apresentar opções claras:

**SCA — Dependências**

Analisa componentes, versões e advisories.

**SAST — Código**

Executa regras Semgrep sobre o código.

**Análise combinada**

Executa ambos, quando disponíveis.

### Etapa 3 — Verificar pré-requisitos

Criar uma tela com status dos mecanismos:

- OSV acessível.
- Lockfiles identificados.
- Semgrep instalado.
- Regras carregadas.
- Caminho autorizado.
- Recursos disponíveis.

Exibir mensagens de correção específicas.

Não apresentar variáveis técnicas como única orientação.

### Etapa 4 — Executar análise

Apresentar um job com estados reais:

- Preparando.
- Inventariando.
- Consultando advisories.
- Executando SAST.
- Consolidando.
- Concluído.
- Parcial.
- Falhou.

Mostrar progresso por etapa, duração e erros quando disponíveis.

Não inventar porcentagens de execução.

### Etapa 5 — Resultados

Organizar o resultado em abas:

**Resumo**
- Dependências analisadas.
- Vulnerabilidades.
- Achados SAST.
- Severidade.
- Cobertura.

**SCA**
- Biblioteca.
- Versão.
- CVE/GHSA.
- Severidade.
- Correção.
- Caminho da dependência.

**SAST**
- Regra.
- CWE.
- Severidade.
- Arquivo.
- Linha.
- Evidência.

**Inventário**
- Componentes.
- Versões.
- Ecossistemas.
- Dependências diretas/transitivas.

**Histórico**
- Scans anteriores.
- Novos achados.
- Persistentes.
- Resolvidos.
- Alterações de cobertura.

Cada achado deve ter um painel próprio de investigação.

---

# 8. TECNOLOGIAS E BIBLIOTECAS

Criar uma página para exploração de tecnologias monitoradas.

Organizar por ecossistema:

- npm / JavaScript / TypeScript.
- Node.js runtime.
- Maven / Java.
- PyPI / Python.
- NuGet / .NET.
- Composer / PHP.
- Go.
- Cargo / Rust.
- RubyGems.
- Outros suportados.

Permitir navegar de um ecossistema para as bibliotecas e de uma biblioteca para seus advisories.

Cada tecnologia deve apresentar:

- Nome.
- Ecossistema.
- Vulnerabilidades associadas.
- Últimas divulgações.
- Severidades.
- Versões afetadas disponíveis.
- Referências oficiais.
- Botão de monitoramento.

Evitar associação apenas por palavras-chave quando houver identificadores estruturados de pacote.

---

# 9. WATCHLIST — MONITORAMENTO ÚTIL

Substitua a página de formulário simples por um painel de acompanhamento.

Criar visualizações para:

- Todas as tecnologias monitoradas.
- Tecnologias com novas vulnerabilidades.
- Tecnologias com KEV.
- Alertas recentes.
- Histórico.

Adicionar biblioteca ou tecnologia por um diálogo compacto.

Cada item deve permitir:

- Definir ecossistema.
- Informar versão opcional.
- Configurar severidade mínima.
- Configurar alertas.
- Abrir vulnerabilidades relacionadas.
- Remover item.

Quando a lista estiver vazia, criar um empty state profissional com ação direta e exemplos de componentes que podem ser acompanhados.

Não preencher automaticamente com registros fictícios.

---

# 10. CENTRAL DE PRIORIDADES E REMEDIAÇÃO

Criar uma página específica para o processo operacional de AppSec.

O analista precisa entender:

1. O que está vulnerável?
2. Qual aplicação está afetada?
3. Qual biblioteca está envolvida?
4. Qual versão está instalada?
5. Existe correção?
6. Existe exploração conhecida?
7. Qual é o próximo passo?

Criar filas de trabalho:

- Investigação imediata.
- Pendentes.
- Em análise.
- Correção planejada.
- Em remediação.
- Resolvidos.
- Não aplicáveis.
- Risco aceito.

Permitir visualizar detalhes e registrar justificativas.

Não tratar vulnerabilidades globais sem correspondência com ativos como achados confirmados do ambiente.

---

# 11. ALERTAS E THREAT INTELLIGENCE CONTÍNUA

Criar uma central de notificações com:

- Novas vulnerabilidades.
- Novas entradas KEV.
- Atualizações de advisories.
- Novas correspondências com pacotes monitorados.
- Novos achados de scans.
- Disponibilidade de correções.
- Falhas de sincronização.

Permitir configurar notificações por severidade, tecnologia e projeto.

Oferecer webhooks e integração opcional com Microsoft Teams, Slack e SMTP.

Deduplicar notificações e evitar alertas repetidos sem alteração material.

O monitoramento deverá atualizar a interface por SSE ou WebSocket, com reconexão automática.

A atualização visual em tempo real não deve ser confundida com publicação instantânea das fontes.

---

# 12. FONTES E SINCRONIZAÇÃO

Criar um painel de saúde das integrações.

Mostrar individualmente:

- NVD.
- GitHub Security Advisories.
- OSV.
- CISA KEV.
- FIRST EPSS.
- Fontes complementares implementadas.

Para cada fonte:

- Status.
- Última tentativa.
- Última sincronização bem-sucedida.
- Duração.
- Registros novos.
- Registros atualizados.
- Erros.
- Estado de paginação.
- Limites de consulta.

Distinguir:

- Saudável.
- Sincronizando.
- Parcial.
- Atrasada.
- Indisponível.

Não utilizar apenas um indicador genérico “Atualizado”.

---

# 13. ORGANIZAÇÃO DOS DADOS E MODELO DE INFORMAÇÃO

O backend deve refletir a mesma lógica que o usuário vê na interface.

Organize os conceitos:

**Advisory:** publicação fornecida por uma fonte.

**Vulnerability:** vulnerabilidade consolidada e seus aliases.

**Affected Component:** produto ou pacote relacionado a um advisory, com intervalos de versões.

**Technology:** ecossistema, runtime ou framework.

**Repository:** aplicação cadastrada.

**Dependency Inventory:** componentes identificados em um projeto.

**Finding:** resultado de SCA ou SAST.

**Scan:** execução de análise com escopo, cobertura e status.

**Triage:** estado de investigação e remediação.

**Alert:** evento relevante para acompanhamento.

**Source Sync:** execução da coleta com seus indicadores de saúde.

As interfaces devem exibir esses conceitos de forma consistente.

### Regras de consistência

- Não contar GHSA e CVE associados como duas vulnerabilidades distintas sem justificativa.
- Não confundir a severidade de um advisory com o risco específico de uma aplicação.
- Não misturar data de publicação com data da última coleta.
- Não interpretar ausência de CVSS como severidade baixa.
- Não apresentar EPSS como probabilidade de comprometimento do usuário.
- Não associar bibliotecas a CVEs sem evidências confiáveis.
- Não indicar que uma vulnerabilidade está corrigida sem evidência.
- Não apresentar valores agregados sem informar o conjunto e o período analisados.

---

# 14. QUALIDADE DE IMPLEMENTAÇÃO

Mantenha a arquitetura proposta anteriormente:

- React + TypeScript + Vite no frontend.
- Tailwind CSS e componentes acessíveis.
- FastAPI no backend.
- SQLAlchemy e Alembic.
- SQLite local e PostgreSQL opcional.
- Integrações NVD, GitHub, OSV, KEV e EPSS.
- Semgrep para SAST.
- Parsers confiáveis de lockfiles e SBOM para SCA.
- Jobs persistentes e coleta incremental.
- Testes automatizados.
- GitHub Actions.
- Distribuição para Windows.

A migração de qualquer código existente deve preservar dados e funcionalidades válidas.

O projeto precisa manter:

- Persistência confiável.
- Segurança de caminhos locais.
- Validação de entradas.
- Controle de concorrência.
- Proteção de credenciais.
- Limites de recursos.
- Tratamento de falhas.
- Logs estruturados.
- Separação frontend/backend.
- Instalação documentada.

Não execute scripts de build de repositórios analisados sem autorização e isolamento apropriados.

---

# 15. RESPONSIVIDADE E DETALHES VISUAIS

Valide a interface nas seguintes larguras:

- 1920 px.
- 1440 px.
- 1366 px.
- 1024 px.
- 768 px.
- 390 px.

### Desktop

Utilizar grid responsivo, sidebar e conteúdo principal com largura adequada.

Evitar áreas gigantes vazias e também excesso de conteúdo comprimido.

### Notebook

Priorizar visualização útil acima da dobra.

Tabelas podem oferecer rolagem horizontal controlada e personalização de colunas.

### Mobile

Sidebar deve se transformar em navegação apropriada para telas pequenas.

Tabelas precisam de uma alternativa utilizável.

Modais, drawers e formulários não podem ultrapassar a viewport.

### Acessibilidade

- Contraste suficiente.
- Foco visível.
- Semântica HTML.
- Rótulos adequados.
- Navegação por teclado.
- Estados de erro.
- Suporte a redução de movimento.
- Tooltips acessíveis.

Objetivo: WCAG 2.2 AA.

---

# 16. VALIDAÇÃO VISUAL OBRIGATÓRIA

Não declare o redesign concluído apenas porque o CSS foi alterado.

Utilize Playwright ou outra ferramenta adequada para:

1. Abrir todas as rotas.
2. Capturar screenshots reais.
3. Inspecionar espaçamento e alinhamento.
4. Testar responsividade.
5. Validar drawers e modais.
6. Exercitar filtros e tabelas.
7. Verificar pesquisa.
8. Verificar estados de erro e loading.
9. Validar navegação por teclado.
10. Corrigir problemas encontrados.

Compare o resultado com as capturas originais.

Uma mudança visual só é relevante se melhorar hierarquia, legibilidade, organização ou eficiência de uso.

Exija testes funcionais de frontend e backend, incluindo integração real das telas com endpoints.

Não use dados mockados para declarar que a coleta real está funcionando.

---

# 17. PERFORMANCE E ESTADOS OPERACIONAIS

O frontend não deve carregar milhares de vulnerabilidades de uma só vez.

Implementar:

- Paginação server-side.
- Virtualização de tabelas quando justificada.
- Cache de consultas.
- Debounce.
- Carregamento sob demanda.
- Estados de sincronização.
- Cancelamento de requisições obsoletas.
- Atualizações incrementais.
- Limites de renderização.
- Estratégia de tratamento de erros.

As consultas devem ser verificáveis e responsivas.

A ausência de dados, a falha de uma API e a ausência de permissão devem gerar estados visuais distintos.

---

# 18. ENTREGÁVEIS OBRIGATÓRIOS

Ao concluir, o repositório deverá conter:

**Produto**
- Dashboard redesenhado.
- Feed profissional.
- Busca universal.
- Investigação de vulnerabilidades.
- Central de tecnologias.
- Análise de repositórios.
- Resultados SCA/SAST.
- Watchlist.
- Central de prioridades.
- Alertas.
- Histórico.
- Configurações.

**Engenharia**
- Backend funcional.
- Banco e migrações.
- APIs documentadas.
- Frontend integrado.
- Serviços de coleta.
- Testes.
- CI/CD.
- Build Windows.
- Docker opcional.
- Segurança e documentação.

**Design**
- Design system.
- Tokens de tema.
- Componentes reutilizáveis.
- Capturas reais de todas as páginas.
- Estados vazios, carregamento e erro.
- Responsividade validada.

---

# 19. PLANO DE EXECUÇÃO DO CODEX

Execute nesta sequência:

### Fase 1 — Auditoria

Analise todo o repositório, os fluxos e as imagens fornecidas.

Identifique problemas de UI, UX, organização de dados, backend e integração.

### Fase 2 — Arquitetura da informação

Defina navegação, relação entre páginas, entidades e jornadas de uso.

Documente o mapa de telas e os fluxos principais.

### Fase 3 — Design system

Implemente tokens, tipografia, layouts, componentes, estados e padrões de interação.

### Fase 4 — Dashboard e investigação

Redesenhe completamente o dashboard, feed, busca, detalhes de CVE e tecnologias.

### Fase 5 — Application Security

Implemente a nova experiência de cadastro de repositórios, SCA, SAST, inventário, resultados e histórico.

### Fase 6 — Gestão operacional

Implemente watchlist, alertas, triagem, prioridades e relatórios.

### Fase 7 — Integrações e consistência

Verifique endpoints, dados, consultas, persistência, correspondência de versões e correlação entre módulos.

### Fase 8 — Testes e refinamento

Execute testes unitários, integração e navegação com Playwright.

Capture imagens reais e corrija problemas visuais.

### Fase 9 — Entrega

Atualize README, AGENTS.md, documentação, workflows GitHub e scripts de execução Windows.

Mantenha `docs/IMPLEMENTATION_STATUS.md` atualizado durante todo o desenvolvimento.

Não interrompa na criação do layout. Continue até implementar e conectar as funcionalidades.

---

# 20. DEFINIÇÃO DE PRONTO

O projeto só poderá ser considerado concluído quando:

- A navegação estiver organizada.
- Todas as páginas tiverem identidade visual consistente.
- Os indicadores utilizarem dados confiáveis.
- O dashboard diferenciar inteligência global e exposição das aplicações.
- A busca por pacote e CVE funcionar.
- O feed permitir investigação eficiente.
- Os scanners SCA/SAST funcionarem nos cenários suportados.
- Os resultados forem persistidos.
- A watchlist funcionar.
- A triagem funcionar.
- Os alertas implementados funcionarem.
- Os estados de sincronização estiverem corretos.
- Os filtros e botões executarem ações reais.
- As páginas forem responsivas.
- A aplicação passar nos testes automatizados aplicáveis.
- O frontend tiver sido testado em navegador.
- A instalação e o build estiverem documentados.
- As limitações forem apresentadas claramente.

Não considere os objetivos cumpridos apenas porque existem arquivos correspondentes.

---

# INSTRUÇÃO FINAL

Você tem autonomia para refatorar profundamente o frontend e reorganizar os módulos, preservando as funcionalidades e dados existentes.

Não quero alterações cosméticas, um protótipo estático nem um projeto superficial com dezenas de páginas vazias.

Quero transformar o Vuln Radar em uma **plataforma de Application Security e Vulnerability Threat Intelligence com qualidade de produto comercial**, capaz de apoiar investigações reais de vulnerabilidades, análise de dependências, avaliação de código e processos de remediação.

**Primeiro organize a informação. Depois implemente a experiência visual. Em seguida, conecte as funcionalidades, execute os testes e refine o resultado.**

Trabalhe diretamente no repositório.

Não faça push remoto sem autorização.

Não declare conclusão sem evidência dos testes.

Se alguma funcionalidade não puder ser implementada, documente o motivo e mantenha o restante funcional.

**Comece agora pela auditoria do repositório, siga todas as fases e entregue o projeto implementado.**
