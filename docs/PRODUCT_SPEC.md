# MASTER PROMPT — VULN RADAR
## Desenvolvimento integral de uma plataforma de Application Security & Vulnerability Threat Intelligence

### 1. MISSÃO E PAPEL

Você é o engenheiro principal responsável pelo desenvolvimento integral do **Vuln Radar**, uma plataforma de inteligência de vulnerabilidades focada em aplicações, bibliotecas, dependências, frameworks, runtimes e repositórios de código.

Atue simultaneamente como:

- Principal Software Engineer
- Software Architect
- Senior Full Stack Developer
- Application Security Engineer
- DevSecOps Engineer
- Vulnerability Research Engineer
- Threat Intelligence Engineer
- Senior Product Designer / UI/UX Engineer
- QA Automation Engineer

**Sua missão não é produzir um planejamento, exemplo de código ou protótipo. Sua missão é desenvolver uma aplicação completa, executável, testável, documentada e preparada para publicação em um repositório GitHub.**

Você deve trabalhar diretamente nos arquivos do projeto.

Se houver código anterior do Vuln Radar, examine tudo antes de decidir o que preservar, refatorar ou substituir.

Se a pasta estiver vazia, implemente a plataforma a partir do zero.

Não faça mudanças desnecessárias apenas para adotar uma tecnologia diferente. Entretanto, não mantenha arquiteturas problemáticas por compatibilidade com um código antigo.

Tome decisões técnicas fundamentadas, priorizando segurança, confiabilidade, desempenho, manutenibilidade e experiência do usuário.

**Requisito fundamental:** o sistema deve ser uma ferramenta operacional de AppSec e Threat Intelligence, não apenas uma interface com informações de demonstração.

---

# 2. OBJETIVO DO PRODUTO

O Vuln Radar deve permitir que analistas de segurança acompanhem continuamente novas vulnerabilidades divulgadas publicamente e identifiquem se bibliotecas, frameworks, runtimes e aplicações que utilizam estão potencialmente afetados.

O produto deverá oferecer:

1. Monitoramento contínuo de novas vulnerabilidades.
2. Feed pesquisável de CVEs e advisories.
3. Correlação de informações entre múltiplas fontes.
4. Identificação de tecnologias, pacotes e versões afetadas.
5. Busca rápida por CVE, GHSA, pacote, runtime e tecnologia.
6. Consulta de vulnerabilidades por versão instalada.
7. Análise SCA de repositórios locais.
8. Análise SAST de código-fonte.
9. Importação e análise de SBOMs.
10. Monitoramento de tecnologias de interesse por watchlist.
11. Priorização com CVSS, EPSS e CISA KEV.
12. Alertas de vulnerabilidades relevantes.
13. Histórico e acompanhamento de correções.
14. Dashboards interativos e gráficos históricos.
15. Exportação de relatórios.
16. Interface web profissional, responsiva e intuitiva.
17. Execução local no Windows via localhost.
18. Arquitetura preparada para implantação futura em servidores.

O Vuln Radar não deve afirmar que encontrou um zero-day desconhecido apenas por identificar uma CVE crítica. Deve diferenciar vulnerabilidades recentemente divulgadas, falhas exploradas ativamente, vulnerabilidades conhecidas antes da publicação de correções e registros com indícios públicos de exploit.

---

# 3. STACK TECNOLÓGICA

Adote preferencialmente a seguinte arquitetura, salvo justificativa técnica documentada.

## Backend

- Python 3.12 ou versão estável comprovadamente compatível.
- FastAPI.
- Pydantic para validação.
- SQLAlchemy 2.x.
- Alembic para migrações.
- httpx para integrações HTTP.
- SQLite como banco padrão local.
- PostgreSQL como opção para implantação em servidor.
- APScheduler ou mecanismo equivalente para tarefas recorrentes em uma única instância.
- Workers assíncronos com persistência para tarefas de varredura.
- Logging estruturado.
- Gerenciamento seguro de configurações e credenciais.

## Frontend

- React.
- TypeScript.
- Vite.
- Tailwind CSS.
- shadcn/ui ou biblioteca equivalente de componentes acessíveis.
- Lucide Icons.
- TanStack Query.
- TanStack Table.
- React Router.
- Recharts, ECharts ou biblioteca apropriada para visualizações.
- React Hook Form e Zod quando aplicáveis.

## Testes e desenvolvimento

- pytest.
- pytest-asyncio.
- Ruff.
- Mypy, quando viável.
- Vitest.
- React Testing Library.
- Playwright.
- GitHub Actions.
- Docker e Docker Compose.

Use dependências mantidas e versões compatíveis verificadas no momento da implementação.

Não instale bibliotecas desnecessárias.

Não dependa de serviços pagos para as funcionalidades fundamentais.

---

# 4. ARQUITETURA DO PROJETO

Organize o repositório de forma modular.

Estrutura de referência:

```text
vuln-radar/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── repositories/
│   │   ├── services/
│   │   │   ├── intelligence/
│   │   │   ├── correlation/
│   │   │   ├── sca/
│   │   │   ├── sast/
│   │   │   ├── sbom/
│   │   │   ├── notifications/
│   │   │   └── reporting/
│   │   ├── integrations/
│   │   ├── collectors/
│   │   ├── workers/
│   │   ├── security/
│   │   └── main.py
│   ├── alembic/
│   ├── tests/
│   ├── pyproject.toml
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── layouts/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── features/
│   │   ├── types/
│   │   └── styles/
│   └── package.json
├── rules/
│   └── semgrep/
├── scripts/
├── docs/
├── tests/
├── .github/
│   └── workflows/
├── .env.example
├── .gitignore
├── Dockerfile
├── compose.yaml
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── AGENTS.md
```

A estrutura pode ser refinada durante a implementação.

Separe claramente domínio, serviços, persistência, integrações, API e interface.

Evite arquivos monolíticos, dependências circulares e lógica de negócio embutida em componentes visuais.

---

# 5. MOTOR DE VULNERABILITY THREAT INTELLIGENCE

Este é um dos componentes mais importantes do sistema.

Implemente um mecanismo robusto de coleta, normalização, correlação, armazenamento e atualização de vulnerabilidades.

## 5.1 Fontes prioritárias

Integrar:

**NVD — National Vulnerability Database**

- CVEs.
- Descrições.
- Publicação e atualização.
- CVSS.
- CWE.
- Produtos afetados.
- CPEs.
- Referências.

**GitHub Security Advisory Database**

- GHSAs.
- CVEs associadas.
- Ecossistemas.
- Bibliotecas afetadas.
- Intervalos vulneráveis.
- Versões corrigidas.
- Referências e datas.

**OSV — Open Source Vulnerabilities**

- Vulnerabilidades por biblioteca.
- Ecossistemas de pacotes.
- Versões vulneráveis.
- Intervalos de versões.
- Aliases.
- Referências.
- Consultas por pacote e versão.

**CISA KEV**

- Vulnerabilidades com exploração conhecida.
- Data de inclusão no catálogo.
- Informações de ação recomendada.
- Evidências e referências disponíveis.

**FIRST EPSS**

- Probabilidade estimada de exploração.
- Percentil.
- Data da estimativa.
- Histórico quando disponibilizado ou coletado.

## 5.2 Fontes complementares

Avalie integrações adicionais com:

- CERT/CC.
- GitLab Advisory Database.
- Red Hat Security Data.
- Debian Security Tracker.
- Ubuntu Security Notices.
- Apache Security Advisories.
- Node.js Security Releases.
- Python Security Advisories.
- Oracle Critical Patch Updates.
- Microsoft Security Update Guide.

Priorize fontes oficiais e APIs documentadas.

Implemente as integrações complementares como conectores independentes. Caso alguma não ofereça interface estável ou acesso viável, documente a limitação e não simule cobertura.

## 5.3 Coleta contínua

O motor deve:

- Executar coletas periódicas.
- Permitir intervalos configuráveis.
- Registrar a última execução por fonte.
- Persistir checkpoints.
- Buscar dados novos e atualizados.
- Implementar paginação.
- Respeitar rate limits.
- Utilizar retries com backoff e jitter.
- Tratar HTTP 429 e falhas temporárias.
- Evitar requisições desnecessárias.
- Deduplicar registros.
- Registrar erros individuais.
- Preservar dados anteriores quando uma fonte falhar.
- Permitir atualização manual.

A frequência configurável deve começar, por padrão, em 60 minutos, sujeita aos limites e à latência de cada fonte.

A ausência de novas CVEs não pode ser confundida com falha de sincronização.

## 5.4 Modelo normalizado

Criar um modelo que represente:

- Identificador canônico.
- Aliases CVE/GHSA/OSV.
- Descrição.
- Severidade informada.
- CVSS, incluindo versão e vetor.
- CWE.
- Data de publicação.
- Data de atualização.
- Fontes.
- Pacotes e produtos afetados.
- Ecossistemas.
- Versões vulneráveis.
- Versões corrigidas.
- EPSS.
- KEV.
- Referências.
- Histórico de alterações.
- Estado de análise e triagem.

Não unir registros exclusivamente pela semelhança do título. Utilize aliases explícitos e evidências confiáveis.

Preserve divergências entre fontes, inclusive severidade e informações sobre versões.

Nunca invente uma versão corrigida quando a fonte não informar uma.

---

# 6. SUPORTE A LINGUAGENS, RUNTIMES E BIBLIOTECAS

A plataforma deve ter foco em segurança de aplicações.

Suportar, conforme cobertura das fontes:

| Ecossistema | Componentes |
|---|---|
| JavaScript / npm | Express, React, Next.js, Axios, Lodash e demais pacotes npm |
| Node.js | Runtime e advisories de segurança |
| Java | Maven, Gradle, Spring, Jackson, Log4j |
| Python | PyPI, Django, Flask, FastAPI, Requests |
| .NET | NuGet e bibliotecas .NET |
| PHP | Composer, Laravel, Symfony |
| Go | Módulos Go |
| Rust | Cargo |
| Ruby | RubyGems |
| Linux | Dependências e pacotes quando houver dados confiáveis |
| Containers | Imagens, bibliotecas de sistema e runtimes, por integração apropriada |

O sistema não pode depender apenas de uma lista fixa de tecnologias.

É necessário pesquisar pacotes arbitrários suportados pelas APIs.

Diferencie uma biblioteca npm do runtime Node.js e um pacote Maven do próprio runtime Java.

Exiba claramente quando uma tecnologia ou versão não tiver cobertura suficiente nas fontes utilizadas.

---

# 7. DASHBOARD PRINCIPAL — SECURITY INTELLIGENCE OVERVIEW

Desenvolva um painel de qualidade visual comparável à experiência de plataformas profissionais como Wiz, Snyk, Linear, Datadog e CrowdStrike, sem copiar diretamente seus componentes.

O dashboard deverá apresentar uma visão operacional clara.

## Indicadores

- Total de vulnerabilidades monitoradas.
- Críticas.
- Altas.
- Novas nas últimas 24 horas.
- Novas nos últimos 7 dias.
- Novas nos últimos 30 dias.
- Vulnerabilidades KEV.
- EPSS acima de limiares configuráveis.
- Tecnologias monitoradas.
- Projetos cadastrados.
- Achados SCA abertos.
- Achados SAST abertos.
- Análises executadas.
- Status das fontes.

## Visualizações

Criar:

1. Gráfico de novas vulnerabilidades por dia.
2. Evolução histórica de publicações.
3. Distribuição por severidade.
4. Distribuição de EPSS.
5. Tecnologias com mais advisories coletados.
6. Vulnerabilidades recentemente adicionadas ao KEV.
7. Vulnerabilidades relevantes para a watchlist.
8. Atividade recente de análises de repositórios.
9. Evolução dos achados abertos e resolvidos.
10. Status de sincronização das fontes.

Gráficos devem possuir filtros temporais e tooltips.

Não apresentar oscilações como tendências de risco real do mercado sem explicar a metodologia e cobertura da coleta.

Ao clicar em um indicador, abrir a listagem correspondente com filtros aplicados.

---

# 8. DESIGN SYSTEM E EXPERIÊNCIA DE USUÁRIO

Quero uma interface premium, moderna, consistente e adequada a uma ferramenta corporativa de segurança.

## Direção visual

Adotar:

- Dark Mode como tema principal.
- Light Mode opcional.
- Paleta neutra com acento azul/ciano controlado.
- Tipografia moderna.
- Ícones consistentes.
- Hierarquia clara.
- Cards compactos e informativos.
- Bordas discretas.
- Sombras sutis.
- Espaçamento padronizado.
- Tabelas densas, porém legíveis.
- Estados de carregamento elegantes.
- Transições discretas.
- Interface responsiva.

Não utilizar cores fluorescentes em excesso, gradients desnecessários, glassmorphism exagerado ou gráficos decorativos.

## Layout

Criar uma sidebar recolhível com:

**Monitoramento**
- Visão geral.
- Feed de vulnerabilidades.
- Inteligência de exploração.

**Investigação**
- Busca universal.
- Bibliotecas e tecnologias.
- Análise de repositórios.
- Resultados SCA/SAST.

**Gestão**
- Watchlist.
- Alertas.
- Triagem.
- Relatórios.

**Sistema**
- Fontes e sincronização.
- Histórico.
- Configurações.

A topbar deve conter busca global, estado de atualização e acesso aos eventos importantes.

Não espalhar formulários por toda a página. Utilize filtros compactos, drawers, modais e painéis contextuais.

## Requisitos de UX

- Navegação por teclado.
- Estados vazios úteis.
- Skeleton loading.
- Tratamento visual de erros.
- Toast notifications.
- Tabelas com paginação.
- Filtros persistentes quando apropriado.
- Busca com debounce.
- Ordenação.
- Tooltips informativos.
- Acessibilidade WCAG 2.2 AA como objetivo verificável.
- Layout adequado para desktop e notebook.

Todos os botões devem possuir ações funcionais.

---

# 9. FEED DE VULNERABILIDADES

Criar um feed de investigação profissional.

## Colunas principais

- CVE/GHSA.
- Título.
- Severidade.
- CVSS.
- EPSS.
- KEV.
- Pacote/produto.
- Ecossistema.
- Data de publicação.
- Data de atualização.
- Fonte.
- Estado da triagem.

## Filtros

Permitir combinar:

- Busca textual.
- CVE.
- GHSA.
- Tecnologia.
- Biblioteca.
- Ecossistema.
- Severidade.
- Intervalo de CVSS.
- Intervalo de EPSS.
- KEV.
- Data de publicação.
- Data de atualização.
- Novas versus atualizadas.
- Status de triagem.

Os filtros avançados devem ficar recolhidos por padrão.

## Detalhamento

Ao clicar em uma vulnerabilidade, abrir drawer lateral com:

- Descrição técnica integral.
- CVSS e vetor.
- CWE.
- Pacotes afetados.
- Intervalos vulneráveis.
- Versões corrigidas.
- Referências.
- Exploração conhecida.
- EPSS.
- Histórico.
- Mitigações documentadas.
- Projetos locais com dependências correspondentes.
- Ações de triagem.

Fornecer links oficiais.

Não confundir pontuação de criticidade com exploração comprovada.

---

# 10. BUSCA UNIVERSAL E PESQUISA DE PACOTES

Criar uma experiência semelhante a um mecanismo de busca especializado.

A busca deve aceitar:

- `CVE-2024-XXXX`
- `GHSA-xxxx-xxxx-xxxx`
- `lodash`
- `express`
- `node`
- `spring-core`
- `openssl`
- Nome de pacote com versão.

A interface deve diferenciar automaticamente identificadores reconhecidos de consultas textuais.

## Modos de busca

**Busca por vulnerabilidade**

Consultar o histórico e, quando necessário, fontes externas.

**Busca por pacote**

Pesquisar advisories relacionados a uma biblioteca.

**Avaliação de versão**

Permitir informar:

- Ecossistema.
- Nome do pacote.
- Versão exata.

Verificar correspondência com os dados de vulnerabilidade disponíveis.

**Busca por tecnologia**

Exibir vulnerabilidades relacionadas a runtimes, frameworks ou produtos, conforme a cobertura existente.

## Resultados

Apresentar:

- Vulnerabilidades identificadas.
- Severidade.
- Referências.
- Intervalos vulneráveis.
- Correção disponível.
- Data da publicação.
- Estado e completude da consulta.

Nunca apresentar uma consulta incompleta como resultado negativo definitivo.

---

# 11. SCA — SOFTWARE COMPOSITION ANALYSIS

Desenvolver um scanner de dependências integrado.

O usuário deve conseguir selecionar um repositório local e executar análise de componentes.

## Formatos iniciais

Implementar parsers confiáveis para:

- package-lock.json.
- yarn.lock.
- pnpm-lock.yaml.
- pom.xml.
- Arquivos de lock do Gradle.
- requirements.txt com versões resolvidas.
- poetry.lock.
- Pipfile.lock.
- go.mod e arquivos de resolução apropriados.
- Cargo.lock.
- composer.lock.
- Arquivos NuGet com versões resolvidas.
- SBOM CycloneDX.

Para formatos sem versões resolvidas, informar limitação de cobertura.

## Fluxo de análise

1. Selecionar repositório.
2. Validar diretório autorizado.
3. Identificar linguagens e gerenciadores de dependências.
4. Localizar manifestos e lockfiles.
5. Extrair dependências.
6. Identificar versões.
7. Consultar OSV e fontes adequadas.
8. Correlacionar advisories.
9. Registrar resultados.
10. Apresentar recomendações de atualização.

## Resultados SCA

Mostrar:

- Biblioteca.
- Versão encontrada.
- Ecossistema.
- Dependência direta ou transitiva, quando identificável.
- Arquivo de origem.
- Caminho de dependência, quando conhecido.
- CVE/GHSA/OSV.
- Severidade.
- Versão corrigida, quando disponível.
- Estado da análise.
- Evidência.
- Links oficiais.

## Recursos adicionais

- Inventário de dependências.
- Comparação entre execuções.
- Novas vulnerabilidades.
- Vulnerabilidades persistentes.
- Vulnerabilidades resolvidas.
- Exportação.
- Histórico por repositório.
- Relação entre bibliotecas vulneráveis e versões utilizadas.

Não assumir explorabilidade apenas pela presença de uma biblioteca vulnerável.

Distinguir correspondência de versão, alcançabilidade e exploração confirmada.

---

# 12. SAST — STATIC APPLICATION SECURITY TESTING

Integrar Semgrep como mecanismo inicial de análise estática.

## Funcionalidades

- Identificação de linguagens suportadas.
- Seleção de regras.
- Execução local.
- Configuração explícita das regras.
- Coleta de resultados.
- Normalização de severidade.
- Correlação com CWE quando disponível.
- Evidência por arquivo e linha.
- Visualização do trecho relevante.
- Recomendação de correção.
- Status de triagem.
- Comparação entre execuções.
- Exportação.

## Categorias de achados

A cobertura dependerá das regras implementadas e da linguagem analisada.

Inclua conjuntos iniciais de regras para riscos como:

- SQL Injection.
- Command Injection.
- Path Traversal.
- SSRF.
- XSS.
- Insecure Deserialization.
- Uso inseguro de criptografia.
- Configurações TLS inseguras.
- Secrets hardcoded.
- Uso de APIs perigosas.
- Validação inadequada de entrada.
- Padrões inseguros de autenticação e autorização.

Não afirmar que uma categoria foi completamente analisada quando as regras não oferecerem cobertura suficiente.

## Segurança

- Executar Semgrep com argumentos seguros.
- Não concatenar entrada do usuário em comandos shell.
- Definir timeout.
- Limitar recursos e concorrência.
- Não enviar código privado para serviços externos sem consentimento explícito.
- Não permitir seleção de diretórios fora das raízes autorizadas.
- Registrar falhas de execução.

Mostrar pré-requisitos de instalação dentro do dashboard.

---

# 13. CENTRAL DE REPOSITÓRIOS

Desenvolver uma área específica para gerenciar repositórios locais.

O usuário poderá cadastrar projetos autorizados, por exemplo:

`C:\Projetos\minha-api`

Cada projeto terá:

- Nome.
- Caminho.
- Linguagens detectadas.
- Gerenciadores de dependências.
- Data da última análise.
- Quantidade de componentes.
- Achados SCA.
- Achados SAST.
- Histórico de scans.
- Estado da análise.
- Tecnologias identificadas.

## Experiência desejada

Criar um fluxo:

**Cadastrar projeto → Detectar tecnologias → Configurar scanner → Executar análise → Acompanhar → Investigar → Corrigir → Revalidar.**

A página deve apresentar progresso baseado em etapas executadas e estados reais.

Implementar análise em jobs, sem bloquear a thread principal da API.

Persistir status das tarefas:

- Pendente.
- Executando.
- Concluída.
- Concluída parcialmente.
- Falhou.
- Cancelada.

Permitir cancelar quando tecnicamente seguro.

Cada execução deverá possuir identificador próprio, timestamps, informações de cobertura e histórico.

---

# 14. WATCHLIST DE TECNOLOGIAS

Criar uma central para monitoramento de componentes de interesse.

O usuário poderá cadastrar:

- Tecnologia.
- Ecossistema.
- Biblioteca.
- Versão específica opcional.
- Criticidade desejada.
- Preferências de alertas.

Exemplos:

- Node.js.
- Express.
- React.
- Next.js.
- Spring Framework.
- OpenSSL.
- MongoDB.
- Axios.
- Lodash.
- Django.

A watchlist deve:

- Correlacionar novas divulgações.
- Apresentar CVEs relacionadas.
- Destacar entradas KEV.
- Mostrar tendências dos advisories coletados.
- Permitir adicionar e remover itens.
- Persistir configurações.
- Disponibilizar histórico.

A correspondência deve considerar ecossistema, identificador de pacote e versões quando configuradas.

Evitar associações falsas por simples ocorrência de palavras na descrição.

---

# 15. ALERTAS E NOTIFICAÇÕES

Criar um mecanismo configurável de alertas.

## Critérios

- Nova CVE crítica.
- Nova CVE alta.
- Nova entrada no CISA KEV.
- EPSS acima de limiar definido.
- Nova vulnerabilidade de uma tecnologia monitorada.
- Vulnerabilidade que afeta uma dependência inventariada.
- Atualização de advisory relevante.
- Nova versão corrigida informada pela fonte.

## Canais

Implementar inicialmente:

- Central de notificações no dashboard.
- Histórico de alertas.
- Webhook genérico configurável.

Preparar integração opcional com:

- Microsoft Teams.
- Slack.
- E-mail SMTP.

Não exigir esses serviços para executar o produto.

Implementar deduplicação, agrupamento, controle de frequência e registro de entrega.

Não utilizar credenciais hardcoded.

---

# 16. GESTÃO E TRIAGEM DE VULNERABILIDADES

Criar estados:

- Novo.
- Pendente de análise.
- Em investigação.
- Confirmado aplicável.
- Não aplicável.
- Falso positivo.
- Mitigação planejada.
- Mitigado.
- Resolvido.
- Risco aceito.

Permitir:

- Justificativa.
- Evidências.
- Comentários.
- Data de atualização.
- Histórico de alterações.
- Associação com repositório.
- Registro de versão corrigida.
- Exportação.

Não marcar automaticamente um achado como falso positivo apenas porque uma ferramenta não o detectou em uma nova execução.

A transição para resolvido deve considerar a cobertura e a comparabilidade entre análises.

---

# 17. PRIORIZAÇÃO DE RISCO

Implementar um mecanismo transparente de priorização.

Considerar, quando disponíveis:

- CVSS.
- EPSS.
- KEV.
- Exploit público confirmado por referência confiável.
- Associação com dependência efetivamente instalada.
- Versão vulnerável identificada.
- Exposição informada pelo usuário.
- Criticidade configurada do projeto.
- Disponibilidade de correção.

Criar classificações como:

- Investigação imediata.
- Alta prioridade.
- Prioridade moderada.
- Monitoramento.
- Dados insuficientes.

Documentar regras e pesos.

Não confundir CVSS com probabilidade de exploração.

Não confundir EPSS com exploração confirmada.

Não calcular um risco preciso quando os dados necessários estiverem ausentes.

---

# 18. BANCO DE DADOS E HISTÓRICO

Criar modelos para:

- Vulnerabilities.
- VulnerabilityAliases.
- Advisories.
- AffectedPackages.
- Sources.
- SyncRuns.
- Technologies.
- WatchlistItems.
- Repositories.
- RepositoryScans.
- Dependencies.
- SCAFindings.
- SASTFindings.
- TriageEvents.
- Alerts.
- Notifications.
- Settings.

A modelagem pode variar desde que represente adequadamente esses conceitos.

Requisitos:

- Migrações Alembic.
- Índices.
- Chaves estrangeiras.
- Integridade.
- Deduplicação.
- Histórico.
- Transações.
- Fechamento correto de conexões.
- Backup.
- Suporte a SQLite local.
- Preparação para PostgreSQL.

Não usar o SQLite de forma que provoque erros de bloqueio durante processos concorrentes.

Implementar encerramento limpo de conexões, workers e serviços.

Considerar especificamente o comportamento de bloqueios de arquivos no Windows.

---

# 19. ATUALIZAÇÃO EM TEMPO REAL

Criar atualização do dashboard sem precisar recarregar manualmente a página.

Utilizar Server-Sent Events ou WebSockets, escolhendo a alternativa adequada.

Atualizar:

- Estado das coletas.
- Novas vulnerabilidades.
- Contadores.
- Novos alertas.
- Progresso de análises.
- Eventos de sincronização.

Implementar reconexão e tratamento de quedas de conexão.

**Importante:** tempo real significa que a interface recebe prontamente eventos produzidos pelo backend. A ferramenta continua limitada à frequência de publicação e consulta das fontes externas.

Não prometer detecção instantânea de CVEs em toda a internet.

---

# 20. SEGURANÇA DA PRÓPRIA PLATAFORMA

Esta ferramenta processará caminhos locais, manifests e códigos que podem ser confidenciais.

Aplicar práticas de Secure by Design.

## Controles obrigatórios

- Bind padrão em 127.0.0.1.
- Validação de entradas.
- CORS restritivo.
- Proteção contra CSRF quando aplicável.
- Prevenção de XSS.
- Consultas SQL parametrizadas.
- Prevenção de path traversal.
- Proteção contra acesso por symlinks e junctions fora das raízes autorizadas.
- Prevenção de command injection.
- Timeouts de scans.
- Limites de recursos.
- Controle de concorrência.
- Tratamento de arquivos muito grandes.
- Proteção de tokens e secrets.
- Logs sem credenciais.
- Dependências atualizadas.
- Proteção contra requisições indevidas ao backend local.

## Análise de código não confiável

Não executar scripts de instalação de dependências do repositório analisado por padrão.

Não executar código arbitrário proveniente do repositório.

Não utilizar `shell=True` com entradas controladas pelo usuário.

Não permitir alteração de configurações críticas sem validação.

Para eventual implantação remota, exigir uma camada apropriada de autenticação, autorização, TLS e isolamento de scans.

A versão local não deve ser considerada segura para exposição pública automaticamente.

---

# 21. CONFIGURAÇÕES DO SISTEMA

Criar página de configurações com:

- Intervalo de atualização.
- Fontes habilitadas.
- Chaves de API.
- Watchlist.
- Política de retenção.
- Limites de consultas.
- Número máximo de scans concorrentes.
- Diretórios autorizados.
- Regras Semgrep.
- Preferências de notificação.
- Tema visual.
- Configurações de exportação.
- Informações do banco.
- Backup e restauração, mediante validação.

As credenciais devem ser armazenadas com mecanismos apropriados ao ambiente, sem exposição no frontend, logs ou repositório Git.

---

# 22. RELATÓRIOS E EXPORTAÇÃO

Implementar exportação para:

- CSV.
- JSON.
- SARIF para achados compatíveis.
- CycloneDX para inventário de componentes.
- PDF opcional para relatórios executivos.

Relatórios de análise devem conter:

- Projeto.
- Data da execução.
- Ferramentas utilizadas.
- Escopo.
- Dependências analisadas.
- Vulnerabilidades encontradas.
- Severidade.
- Referências.
- Evidências.
- Recomendações.
- Estado da triagem.
- Limitações de cobertura.

Proteger exportações CSV contra formula injection.

Não incluir tokens ou secrets nos relatórios por padrão.

---

# 23. EXPERIÊNCIA DE INSTALAÇÃO NO WINDOWS

A ferramenta será utilizada inicialmente no Windows 10/11.

Criar uma instalação simples.

## Requisitos

- Script de instalação.
- Script de inicialização.
- Ambiente virtual isolado.
- Verificação de dependências.
- Configuração automática do banco.
- Migrações iniciais.
- Inicialização do backend.
- Build e disponibilização do frontend.
- Abertura automática do navegador, quando configurada.

Endereço padrão:

`http://127.0.0.1:8000`

## Executável

Preparar um mecanismo para gerar um executável Windows usando PyInstaller ou solução adequada.

O executável deverá iniciar a aplicação local, servir os arquivos estáticos do frontend compilado e abrir o navegador.

Dados persistentes devem ficar em um diretório apropriado do usuário, como `%LOCALAPPDATA%\VulnRadar`.

Não armazenar o banco dentro de diretórios temporários utilizados pelo empacotamento.

Não afirmar que o executável foi testado no Windows se o build tiver ocorrido apenas em Linux.

Fornecer workflow de build Windows no GitHub Actions, com artefato para download.

---

# 24. DOCKER E DEPLOY FUTURO

Criar:

- Dockerfile multi-stage.
- compose.yaml.
- Healthcheck.
- Volumes persistentes.
- Variáveis de ambiente documentadas.
- Configuração de PostgreSQL opcional.
- Logs.
- Procedimentos de atualização.

Não expor endpoints de varredura de arquivos do host por padrão.

Documentar limitações do scanner em containers e como disponibilizar diretórios de forma explícita e restrita.

---

# 25. TESTES AUTOMATIZADOS

Crie uma suíte robusta de testes.

## Backend

Testar:

- Coleta.
- Normalização.
- Aliases.
- CVSS.
- EPSS.
- KEV.
- Paginação.
- Retry.
- Falha parcial.
- Rate limit.
- Persistência.
- Migrações.
- Deduplicação.
- SCA.
- Parsers.
- SAST.
- Jobs.
- Alertas.
- Triagem.
- Segurança dos endpoints.

## Frontend

Testar:

- Componentes.
- Navegação.
- Formulários.
- Filtros.
- Tabelas.
- Estados vazios.
- Erros de API.
- Atualização de dados.
- Busca universal.
- Detalhes de CVE.
- Scanner de repositórios.

## End-to-end

Com Playwright:

1. Iniciar aplicação.
2. Abrir dashboard.
3. Executar uma pesquisa.
4. Aplicar filtros.
5. Abrir detalhes de uma vulnerabilidade.
6. Cadastrar tecnologia na watchlist.
7. Cadastrar repositório autorizado.
8. Executar SCA em projeto de teste.
9. Verificar resultado.
10. Exportar relatório.

Utilize fixtures e mocks para testes reproduzíveis.

Inclua testes reais de integração com APIs externas em uma suíte separada e opcional, distinguindo resultados de mocks e resultados reais.

Crie um repositório de exemplo seguro, com dependências e versões conhecidas nos fixtures, para validação do motor SCA.

Não misture informações fictícias com o banco de produção.

---

# 26. CI/CD E PREPARAÇÃO PARA GITHUB

O projeto será publicado em um repositório GitHub.

Preparar:

- .gitignore.
- README.md.
- LICENSE, com escolha explícita de licença.
- CONTRIBUTING.md.
- SECURITY.md.
- AGENTS.md.
- .env.example.
- GitHub Actions.
- Testes automatizados.
- Lint.
- Typecheck.
- Build frontend.
- Build backend.
- Compilação Windows.
- Verificação de dependências.

Não incluir:

- Tokens.
- Senhas.
- Arquivos .env reais.
- Bancos com dados privados.
- Repositórios de terceiros analisados.
- Credenciais de API.
- Logs com informações sensíveis.
- Diretórios temporários.
- Artefatos locais de build.
- node_modules.
- Ambientes virtuais.

Criar workflows para execução em pull requests e na branch principal.

Utilizar permissões mínimas de GITHUB_TOKEN.

Não configurar publicação automática de releases sem autorização.

Não executar push remoto nem sobrescrever branches existentes sem instrução explícita do proprietário.

---

# 27. PERFORMANCE E CONFIABILIDADE

A aplicação deve suportar bases locais com dezenas de milhares de vulnerabilidades sem carregar todos os registros no navegador.

Implementar:

- Paginação no backend.
- Índices de pesquisa.
- Consultas eficientes.
- Cache com validade configurável.
- Atualização incremental.
- Processamento assíncrono.
- Jobs persistentes.
- Limites de concorrência.
- Proteção contra requisições excessivas.
- Indicadores de saúde do sistema.

Evitar N+1 queries.

Não bloquear o frontend enquanto um scanner executa.

Não perder dados existentes durante falhas de integração.

Não apagar resultados válidos quando uma coleta parcial falhar.

---

# 28. DOCUMENTAÇÃO OBRIGATÓRIA

Produzir documentação clara, em português do Brasil.

## README

Incluir:

- Objetivo.
- Funcionalidades implementadas.
- Capturas reais da interface.
- Arquitetura.
- Requisitos.
- Instalação Windows.
- Instalação Linux.
- Configuração das APIs.
- Execução local.
- Execução de testes.
- Compilação Windows.
- Docker.
- Segurança.
- Limitações conhecidas.

## Documentação técnica

Criar:

- Arquitetura e fluxo de dados.
- Diagrama de componentes.
- Modelagem de banco.
- Contratos de API.
- Processo de normalização.
- Estratégia de correlação.
- Funcionamento SCA.
- Funcionamento SAST.
- Modelo de priorização.
- Estratégia de coleta.
- Tratamento de falhas.
- Threat model da plataforma.
- Procedimento de backup.

Todas as instruções devem corresponder à implementação real.

---

# 29. PLANO DE EXECUÇÃO OBRIGATÓRIO

Trabalhe em fases, mas não pare após entregar o planejamento.

## Fase 1 — Inspeção e arquitetura

- Inspecionar repositório.
- Identificar recursos reutilizáveis.
- Definir arquitetura.
- Criar estrutura.
- Estabelecer padrões de código.
- Configurar ambiente e testes.

## Fase 2 — Backend essencial

- Banco de dados.
- Modelos.
- Migrações.
- APIs.
- Configurações.
- Coletor NVD.
- Coletor GitHub.
- Integração OSV.
- KEV e EPSS.
- Normalização.
- Histórico.

## Fase 3 — Dashboard e investigação

- Design system.
- Layout.
- Dashboard.
- Feed.
- Busca universal.
- Detalhes.
- Filtros.
- Gráficos.
- Status das fontes.

## Fase 4 — AppSec

- Cadastro de repositórios.
- Parsers de dependências.
- SCA.
- Integração Semgrep.
- SAST.
- Histórico de análises.
- Resultados consolidados.

## Fase 5 — Monitoramento operacional

- Watchlist.
- Priorização.
- Alertas.
- Triagem.
- Notificações.
- Atualização da interface em tempo real.
- Relatórios.

## Fase 6 — Qualidade e distribuição

- Auditoria de segurança.
- Testes unitários.
- Testes de integração.
- Testes end-to-end.
- Otimizações.
- Build Windows.
- Docker.
- GitHub Actions.
- Documentação.

Ao final de cada fase:

1. Executar testes relevantes.
2. Corrigir erros.
3. Atualizar documentação.
4. Registrar o que foi implementado.
5. Continuar para a próxima fase.

Não deixar componentes incompletos aparentando estar prontos.

Se houver limitação de contexto, manter um arquivo `docs/IMPLEMENTATION_STATUS.md` com decisões, progresso, problemas pendentes e próximos passos, de modo que a execução possa ser retomada com precisão.

---

# 30. CRITÉRIOS DE ACEITE

O sistema somente poderá ser considerado concluído quando:

- Backend funcionar.
- Frontend funcionar.
- Banco persistir dados.
- Migrações funcionarem.
- Dashboard utilizar dados reais.
- Feed de CVEs funcionar.
- Pesquisa por CVE/GHSA funcionar.
- Pesquisa por pacote e versão funcionar para ecossistemas suportados.
- KEV e EPSS estiverem integrados.
- Watchlist persistir e correlacionar advisories.
- SCA analisar repositórios de teste.
- SAST executar com regras configuradas.
- Histórico de scans funcionar.
- Triagem persistir.
- Alertas funcionarem nos canais implementados.
- Exportação funcionar.
- Atualização periódica funcionar.
- Interface apresentar corretamente erros e estados incompletos.
- Testes automatizados passarem.
- Testes de navegação forem executados.
- Instalação estiver documentada.
- Build Windows estiver configurado.
- Repositório estiver preparado para GitHub.

Funcionalidades não validadas deverão ser documentadas explicitamente.

Não declarar 100% de cobertura SAST, SCA ou de vulnerabilidades mundiais.

---

# 31. PADRÃO DE ENTREGA

Ao concluir, apresente:

### Implementação

- Arquitetura final.
- Funcionalidades desenvolvidas.
- Integrações concluídas.
- Limitações.
- Arquivos e módulos principais.

### Qualidade

- Testes executados.
- Testes aprovados.
- Testes falhos.
- Cobertura, se medida.
- Vulnerabilidades identificadas na própria aplicação.
- Correções aplicadas.

### Interface

- Capturas reais do dashboard.
- Capturas do feed.
- Busca de pacotes.
- Análise de repositório.
- Watchlist.
- Resultados SCA/SAST.

### Execução

- Comandos exatos para instalar.
- Comandos para executar no Windows.
- Comandos para executar os testes.
- Comandos para gerar o executável.
- Procedimento de publicação no GitHub.

Não apresentar screenshots artificiais como se fossem da aplicação funcionando.

---

# 32. REGRAS FINAIS PARA O CODEX

**Regra 1:** não entregue somente um plano. Desenvolva o sistema.

**Regra 2:** não implemente apenas o frontend. Desenvolva backend, integrações, persistência, segurança e testes.

**Regra 3:** não utilize dados fictícios como dados reais.

**Regra 4:** não declare funções implementadas se elas não estiverem conectadas e operacionais.

**Regra 5:** não substitua tratamento de erros por exceções ignoradas.

**Regra 6:** não confunda ausência de vulnerabilidades identificadas com comprovação de segurança.

**Regra 7:** não faça hardcode de CVEs, tecnologias, resultados ou credenciais.

**Regra 8:** não execute código não confiável de repositórios analisados sem isolamento e autorização apropriados.

**Regra 9:** não interrompa o trabalho após criar arquivos básicos. Continue pelas fases de implementação.

**Regra 10:** valide backend e frontend antes de declarar conclusão.

**Regra 11:** priorize funcionamento real, segurança e precisão dos dados sobre quantidade de funcionalidades.

**Regra 12:** não afirme que o projeto está completo quando houver critérios obrigatórios não atendidos.

**Regra 13:** mantenha um registro rastreável do trabalho, com problemas, decisões, testes e limitações.

**Regra 14:** não publique arquivos sensíveis no Git.

**Regra 15:** nunca execute push, force-push ou operações destrutivas sobre o repositório remoto sem autorização.

---

# INSTRUÇÃO FINAL — INICIAR O DESENVOLVIMENTO

Agora examine integralmente o diretório de trabalho e implemente o **Vuln Radar** como uma plataforma funcional de Application Security e Vulnerability Threat Intelligence.

Trate este documento como a especificação principal do produto.

Comece verificando a estrutura existente, documente rapidamente as decisões arquiteturais e prossiga para a implementação.

Desenvolva componentes reais, conectados, seguros, persistentes e testáveis.

Execute os testes à medida que desenvolve e corrija os problemas encontrados.

Ao atingir um limite de execução ou contexto, registre precisamente o estado do desenvolvimento para continuação, sem declarar conclusão prematura.

O objetivo final é um repositório GitHub organizado, com código de produção, testes automatizados, interface profissional, documentação, instalação local e funcionalidades efetivas de Threat Intelligence, SCA e SAST.

**Implemente o produto. Não entregue apenas sua descrição.**
