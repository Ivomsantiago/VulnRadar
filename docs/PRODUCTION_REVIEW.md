# Revisão de produção — 08/11/2026

## Parecer

A revisão implementa correções de integridade, segurança HTTP, instalação Windows e UX. **Não aprova implantação pública ou multiusuário.** A aplicação continua sendo uma instalação local de instância única, com fontes externas reais e análises limitadas pela cobertura disponível. A revisão não equivale a um pentest completo nem a uma certificação de produção.

## Direção de produto

O VulnRadar indexa e correlaciona vulnerabilidades de aplicações, frameworks, bibliotecas, dependências e runtimes. Jornada principal: pesquisar tecnologia/pacote/versão → consultar fontes e divergências → relacionar com inventário → validar aplicabilidade → registrar responsável e remediação → verificar novamente.

NVD, GitHub Advisories, OSV, CISA KEV e FIRST EPSS continuam integrados. CVSS expressa severidade; EPSS é uma estimativa estatística; KEV registra exploração conhecida. Nenhum desses sinais, isoladamente, demonstra exploração de uma aplicação local. Ausência de correspondência não comprova segurança.

**Grype e Trivy foram retirados da execução operacional.** A API antiga responde 410, o worker recusa executar OCI e o instalador legado não baixa binários. Configurações e navegação deixam de recomendar esses mecanismos. Normalização de relatórios antigos, inventários, achados e exportações permanecem compatíveis; `/oci` permite consultar o histórico recente e navegar aos achados anteriores. Os documentos V3 descrevem a entrega histórica e não substituem esta decisão de produto.

## Correções e decisões

| Área | Problema observado | Implementação |
| --- | --- | --- |
| Correlação | O último conector a atualizar um advisory sobrescrevia o resumo, inclusive com severidade desconhecida e texto vazio | Resumo recalculado entre as avaliações armazenadas, independente da ordem de ingestão |
| Datas | Publicação podia ficar ausente e atualização regredir ao receber outra fonte | Primeira publicação e última atualização válidas normalizadas para UTC |
| Severidade | Valor conhecido podia desaparecer; um CVSS removido pela fonte podia permanecer no resumo | Maior severidade e CVSS das avaliações atuais; revisão da fonte pode reduzir o resumo quando não há outra evidência que sustente o valor antigo |
| Transparência | Faltava explicitar a política de resumo na investigação | Política retornada pela API e exibida ao lado das avaliações por fonte |
| Cobertura | Faltava uma visão consolidada das lacunas do índice | `/api/intelligence/quality` e painel em Fontes: registros sem severidade, CVSS, EPSS, descrição ou publicação |
| Saúde das fontes | Atraso usava intervalo do ambiente, ignorando o agendamento salvo; OSV sob demanda podia parecer atrasado como um feed | Usa intervalo persistido; OSV permanece avaliado como consulta sob demanda |
| HTTP | Limite de entrada dependia do Content-Length informado pelo cliente | Middleware ASGI limita os bytes recebidos, incluindo streaming sem tamanho ou cabeçalho subestimado; rejeita tamanho negativo/inválido |
| Integrações | Erros transitórios de transporte não tinham o retry dos erros HTTP | Até quatro tentativas com backoff, propagando a falha definitiva |
| Windows | Alembic separava caminhos com espaços ao ser invocado da raiz | `path_separator = os`, com regressão executando a mesma chamada do instalador |
| Navegador | Playwright assumia caminho Linux para Chromium | Usa navegador instalado pelo Playwright ou override explícito por ambiente |
| UI | Fluxo OCI promovia ferramentas fora do escopo atual | Substituído por histórico e links para pesquisa, feed e inventário; ajustes de quebra de texto, títulos e contenção de rolagem |

Texto de resumo prioriza descrições não vazias de NVD, GitHub e OSV, nessa ordem. Avaliações originais continuam na investigação. Maior CVSS entre versões de métricas é uma política conservadora de apresentação, não uma nova avaliação CVSS local. Reprocessamento de um advisory recalcula seu resumo; não houve reescrita em massa do banco operacional.

## Preservação e segurança

Nenhuma migração destrutiva, remoção de achados ou inserção de fixtures no banco operacional. KPIs de exposição continuam derivados de achados observados. Testes de comparação, resolução, reabertura, migrações e análises parciais continuam na suíte. Nenhum script de repositório analisado foi executado. Não houve push, publicação ou envio externo de notificações.

## Validação desta revisão

- Backend: **99 aprovados, 10 ignorados** na execução padrão Windows. Sete ignorados são integrações opt-in, executadas separadamente com **7 aprovadas**. Os outros são Semgrep real não instalado e dois testes de symlink sem permissão do sistema.
- Frontend: **7 aprovados**, TypeScript e build aprovados; npm reportou zero vulnerabilidades conhecidas na instalação das dependências.
- Playwright: **12 cenários aprovados** em execuções direcionadas: seis de navegação/investigação, CPE/monitoramento/PDF, OCI descontinuado, qualidade do índice e acessibilidade; seis de responsividade. São 18 rotas em 1920, 1440, 1366, 1024, 768 e 390 px, sem overflow global ou falhas de API nessas navegações.
- Axe: cenários automatizados nas páginas e drawers, incluindo temas claro e escuro. Não é auditoria humana WCAG completa.
- Ruff, compatibilidade das dependências Python e `git diff --check` aprovados.
- `pip-audit -r backend/requirements.txt --no-deps --disable-pip`: nenhum advisory conhecido encontrado nas versões fixadas consultadas. A opção sem resolução depende da completude do inventário de versões; não audita imagens base ou um eventual ambiente diferente. `npm audit --audit-level=high`: zero vulnerabilidades reportadas.
- Banco do navegador criado exclusivamente por `scripts/start_test_server.py --mock-osv`. O transporte OSV desse servidor é fictício e isolado; as sete verificações externas acima usaram APIs reais. Não há validação de coleta mundial ou execução de SAST real nesta sessão.

Capturas reais de interface, com dados de teste identificados: [fontes desktop](screenshots/production-review/sources-1440.png), [fontes mobile](screenshots/production-review/sources-390.png), [visão geral desktop](screenshots/production-review/overview-1440.png) e [visão geral mobile](screenshots/production-review/overview-390.png). Não representam o banco operacional.

## Critérios ainda pendentes para produção remota

1. Autenticação, autorização por função/projeto, identidade de autor na auditoria e gestão de sessões. Host/Origin/cabeçalho de cliente não substituem esses controles.
2. TLS, isolamento de processos/arquivos e política de egress, incluindo proteção externa contra DNS rebinding em notificações.
3. Testes de carga, recuperação de jobs e modelo de coordenação antes de operar com múltiplos workers. A arquitetura atual suporta uma instância/worker por banco.
4. Rotina de backup/restauração e retenção validada no ambiente de destino; o script de backup existente não é um plano completo de continuidade.
5. Validação real de SAST no sistema de destino, testes de symlink com privilégios apropriados e revisão humana de acessibilidade. Docker, PostgreSQL e binário Windows não foram executados nesta revisão.
6. Política explícita para advisories retirados/rejeitados e reavaliação do inventário após mudanças nas fontes. Esta revisão não implementa um ciclo completo de retirada de advisory nem recorrelação automática de todo o inventário.

O estado real é uma base local melhor validada e alinhada ao indexador solicitado, com pendências explícitas de produção. Não se declara revisão exaustiva de cada linha nem prontidão integral do produto.

## Executar e verificar

No checkout instalado, `scripts/start.ps1` inicia em `http://127.0.0.1:8000`. Instalação padrão: `scripts/install.ps1` (Python 3.12 pelo launcher `py` e Node/npm). Configure apenas diretórios de projetos autorizados no `.env` conforme README.

```powershell
# Backend, a partir de backend/
../.venv/Scripts/python.exe -m pytest -q
$env:VULNRADAR_LIVE_TESTS='1'
../.venv/Scripts/python.exe -m pytest -q tests/integration/test_live_sources.py

# Frontend, a partir de frontend/
npm.cmd test
npm.cmd run build
npx.cmd playwright install chromium

# Servidor descartável, a partir da raiz, em outro terminal
.venv/Scripts/python.exe scripts/start_test_server.py --mock-osv

# Navegador, a partir de frontend/
npx.cmd playwright test e2e/accessibility.spec.ts e2e/completion.spec.ts e2e/navigation.spec.ts
$env:VULNRADAR_SCREENSHOT_DIR='test-results/production-review'
npx.cmd playwright test e2e/responsive.spec.ts
```
