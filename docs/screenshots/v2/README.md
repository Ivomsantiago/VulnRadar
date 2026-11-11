# Galeria V2

Registro histórico da V2. A [galeria atual, revisada em 11/11/2026](../readme/README.md), mostra acesso autenticado e a interface em uso na main.

Capturas reais de Chromium com frontend compilado e API executando. O servidor de validação usa banco temporário e repositório de fixture seguro; o código não é executado. A galeria desta entrega foi gerada no modo **OSV real + Semgrep local real**. Não descreve um banco operacional ou dados de um cliente.

No CI, a mesma suíte usa respostas OSV explicitamente fictícias para reprodutibilidade. Esse modo está isolado em `scripts/browser_test_app.py` e não é usado no launcher operacional ou na imagem de produção.

As 17 rotas são capturadas em seis larguras. O Git mantém a galeria completa de 1440 px e o dashboard nas seis larguras; as demais capturas continuam disponíveis nos artefatos do CI.

## Páginas a 1440 px

- [Dashboard](1440/dashboard.png)
- [Prioridades](1440/priorities.png)
- [Feed](1440/feed.png)
- [Busca de pacotes](1440/search.png)
- [Tecnologias](1440/technologies.png)
- [Exploração conhecida](1440/exploration.png)
- [Repositórios](1440/projects.png)
- [SCA](1440/sca.png)
- [SAST](1440/sast.png)
- [Inventário/SBOM](1440/inventory.png)
- [Watchlist](1440/watchlist.png)
- [Alertas](1440/alerts.png)
- [Triagem](1440/triage.png)
- [Relatórios](1440/reports.png)
- [Fontes](1440/sources.png)
- [Histórico](1440/history.png)
- [Configurações](1440/settings.png)
- [Resultado de scan](1440/scan-results.png)
- [Evidência de achado](1440/finding-evidence.png)

## Responsividade

Dashboards: [1920](1920/dashboard.png), [1440](1440/dashboard.png), [1366](1366/dashboard.png), [1024](1024/dashboard.png), [768](768/dashboard.png), [390](390/dashboard.png).

Comparação com a versão anterior: as capturas V1 em `../` foram preservadas. A V2 separa exposição e volume global, dá prioridade à fila de achados, recolhe filtros em drawer e apresenta evidências/versões por abas. Os conjuntos de dados das duas galerias são diferentes; não se deve interpretar mudanças nos totais como tendência de risco.
