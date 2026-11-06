# Estado da implementação — V2 — 06/11/2026

Especificações: PRODUCT_SPEC.md (original) e PRODUCT_SPEC_V2.md (evolução). Auditoria e jornadas: V2_AUDIT.md. Base: main `3395cc4`, após merge do PR #1. Branch V2: `feat/vulnradar-v2`.

## Implementação conectada

- Navegação em cinco grupos recolhíveis, sidebar mobile, rotas antigas compatíveis e busca universal Ctrl+K com resultados agrupados.
- Tokens de tema, Tailwind/Vite, números tabulares, tema claro/escuro/sistema, componentes Modal/Drawer nativos, Tabs com teclado, KPIs, skeletons e paginação.
- Dashboard com exposição derivada de achados locais, fila de prioridades, inteligência global separada, gráficos 7/30/60/90 dias, tecnologias e atividade. Ausência de SCA não aparece como zero vulnerabilidades.
- Feed com busca/debounce/cancelamento de consultas obsoletas, filtros em drawer, chips, favoritos locais, colunas, densidade, ordenação e paginação no servidor, seleção/exportação e cartões mobile.
- Investigação em abas com descrição, CVSS/EPSS/KEV/CWE, pacotes, versões/correções/referências, projetos relacionados e histórico. Triagem global de advisory é separada da triagem de achado local.
- Tecnologias com identidades estruturadas, inventário da última análise SCA por projeto e filas SCA/SAST/prioridades/remediação.
- Wizard: seleção de diretórios autorizados, linguagens/lockfiles, opções SCA/SAST/combinada, pré-requisitos, etapas reais, cancelamento e resultados estruturados.
- Migrações aditivas 0003/0004, inventários/achados/observações, backfill idempotente preservando JSON e dados existentes. Comparação completa e compatível pode resolver; parcial não resolve por ausência.
- SAST com regras locais, snapshot sem symlinks/junctions, limites de tamanho agregado/saída/timeout, IDs de regras normalizados, CWE, arquivo/linha e trecho com redação básica de credenciais comuns.
- OSV com paginação, versão opcional e interpretação CVSS 2/3/4 pela biblioteca cvss; severidade MODERATE normalizada para MEDIUM sem alterar evidência original. NVD/GitHub/KEV/EPSS continuam integrados.
- Watchlist editável, severidade mínima/alertas, versões opcionais, verificação manual/agendada, contagens de correspondência e filtro KEV após verificação.
- Preferências e agendamento persistentes, limiar EPSS coerente entre listagem/detalhe, histórico de sincronizações e saúde por fonte.
- Webhook HTTPS opcional, allowlist de host, validação de DNS público, sem redirects, payload restrito, idempotency key e entregas/retries persistidos. Formatos textuais Slack/Teams; nenhum envio externo pelo agente.
- Logs da aplicação em JSON sem corpos, caminhos, cabeçalhos ou texto de exceção. Exportações JSON/CSV/SARIF/CycloneDX preservadas, inclusive scans combinados.

## Evidências

- Backend com integrações reais: **63 testes aprovados**, incluindo a coerência de preferência EPSS e cinco integrações reais; a execução padrão local tem 58 testes e ignora os cinco externos.
- Frontend: **7 testes aprovados**, TypeScript e build de produção aprovados.
- Playwright: **10 cenários aprovados em modo hermético**, com OSV fictício isolado e Semgrep real; **10 aprovados em modo OSV real e Semgrep real**.
- Responsividade: 17 rotas em 1920, 1440, 1366, 1024, 768 e 390 px, sem overflow global e sem erros de API nas navegações verificadas. Cartões mobile para achados/vulnerabilidades.
- Axe: zero violações automáticas nos critérios WCAG A/AA selecionados em 11 páginas, drawer, command palette mobile e configurações com tema claro. Não substitui auditoria humana WCAG completa.
- Ruff, compileall, pip check e npm audit aprovados (audit reportou zero vulnerabilidades). Migração sobre banco 0002 com dados existentes, backfill idempotente, bloqueio de path traversal, estados parciais, reabertura e redação de snippet testados.
- Fontes reais NVD, GitHub, OSV, KEV com espelho oficial e EPSS responderam na suíte opt-in. Consultas reais de OSV e Semgrep também foram exercitadas pelo fluxo de navegador.
- Galeria real em screenshots/v2/; fixtures só em banco descartável, sem dados demonstrativos no launcher operacional.
- CI Linux/build Windows do PR #1 e da main aprovados no GitHub. Workflows V2 atualizados; resultados remotos da V2 devem ser consultados no PR. Executar um binário Windows não foi validado pelo agente.

## Limitações explícitas

1. Deploy remoto: autenticação multiusuário, TLS e sandbox forte de scans ainda são requisitos externos. Esta entrega é local, bind loopback e API com Host/Origin/cabeçalho restritos.
2. Runtimes/produtos CPE não têm inventário estruturado próprio. A pesquisa pode encontrar publicações, mas não associa Node.js runtime a qualquer biblioteca npm nem Java runtime a qualquer pacote Maven. Filtros de linguagem/produto exigem essa modelagem e não são simulados.
3. Parsers de lockfiles têm cobertura inicial, especialmente POM/herança/perfis, Yarn/pnpm históricos e fechamento transitivo Go. Versões não resolvidas geram limitações. SBOM CycloneDX JSON é lido em projetos autorizados e exportado; não há upload web dedicado de SBOM nesta versão.
4. SAST tem seis regras iniciais; não cobre todas as categorias/linguagens. Correspondência SCA ou padrão SAST não comprova alcançabilidade/explorabilidade.
5. SMTP não tem adaptador. Slack/Teams dependem de endpoint textual compatível. Webhooks foram testados com transporte simulado; sem credenciais/destino configurados, nenhum envio externo foi realizado. O receptor precisa tratar idempotência; não há promessa de exactly-once ou agrupamento avançado.
6. Histórico/alertas/sync-runs exibem as últimas 100 entradas. Favoritos/colunas são locais ao navegador. EPSS histórico depende do que foi coletado; não se promete cobertura mundial ou tendência de risco de mercado.
7. Jobs interrompidos são registrados como falha e reenviáveis, sem retomada automática. Uma instância/worker de aplicação por instalação; SQLite não é arquitetura de coordenação distribuída.
8. Docker e PostgreSQL não foram executados nesta sessão. Windows tem workflow de build, mas interação e Semgrep nativo precisam de validação específica. Não incluir alegação de distribuição pronta para SAST nativo Windows.
9. Auditoria humana de acessibilidade, testes com leitores de tela, política de retenção e restauração via UI continuam pendentes. Backup SQLite seguro por script está disponível.
10. Árvores mutáveis por adversários e DNS rebinding exigem isolamento/egress externos adicionais. Hosts de webhook são configuração confiável somente do servidor. Redação de snippet cobre padrões comuns e não equivale a DLP completo.

## Retomada e publicação

Use o checkout existente. Scripts de instalação/start não mudaram de finalidade. Testes de navegador devem usar `scripts/start_test_server.py` (com `--mock-osv` no CI); nunca utilizar o banco operacional para fixtures. Não criar worktree sem pedido explícito.

O ambiente publicado pelo usuário não foi alterado ou republicado nesta etapa. A implementação é enviada em uma branch/PR conforme a autorização anterior de subir o código ao GitHub; não há merge ou release automático.
