# Estado da implementação — 06/11/2026

Especificação principal: [PRODUCT_SPEC.md](PRODUCT_SPEC.md). Repositório inicial: apenas README, commit `98be94c90b29f000e147096c54df4c6a6cf5c6f1`.

**Produto em implementação; critérios completos de aceite ainda não atendidos.** O usuário autorizou enviar a implementação e abrir um pull request. Branch: `feat/vulnradar-platform`. Sem merge ou publicação de release.

## O que existe e foi exercitado

- Python 3.12, FastAPI, SQLAlchemy, SQLite WAL, migração inicial Alembic e ciclo upgrade/downgrade/reupgrade testado.
- React/TypeScript/Vite com páginas separadas, navegação, dashboard, feed, busca OSV, detalhes, watchlist, projetos, scans, fontes, alertas, histórico e configurações efetivas.
- API paginada, aliases/correlação, pacotes afetados indexados, filtros avançados e evidências estruturadas por fonte com referências e correções; persistência de triagem e alertas.
- Conectores NVD/GitHub/KEV/EPSS e OSV implementados; testes locais com mocks. **NVD, GitHub, OSV e EPSS responderam na validação real. O site CISA retornou 403; o espelho oficial `cisagov/kev-data` respondeu e foi integrado como fallback**.
- SCA com múltiplos formatos, casos positivos e negativos com OSV simulado. Falhas de consulta produzem cobertura parcial.
- Semgrep 1.184.0 em `.semgrep-venv`: execução real com regra local de subprocess shell detectou fixture insegura. Sem execução de código do alvo.
- Priorização preliminar explicável, watchlist com consulta por versão e alerta deduplicado, exportação SARIF/CycloneDX/JSON por scan.
- Testes de navegador com Chromium: dashboard, filtros, persistência/remoção watchlist, busca, repositórios e exportação; capturas reais em screenshots/.
- Scripts Linux/PowerShell, Docker/Compose, CI e build PyInstaller Windows preparados. Somente scripts Linux executados.

## Evidência de testes

- Backend: **36 aprovados**, incluindo 5 integrações reais (NVD, GitHub, KEV com fallback oficial, EPSS e OSV). A execução padrão sem opt-in inclui 31 testes locais e ignora os 5 externos.
- Frontend: **3 aprovados**; TypeScript e build de produção aprovados.
- Playwright: **2 cenários aprovados**: navegação/persistência reais e detalhe/evidências/triagem com mocks isolados no navegador. Não cobre ainda todo o roteiro de 10 passos da especificação, especialmente detalhe de advisory real e scan completo via UI.
- npm audit: **0 vulnerabilidades reportadas** nesta instalação. Isto não é auditoria de segurança completa.
- Ruff, pip check, compileall e diff --check aprovados. Instalação Linux reexecutada com npm ci e migrações sem erro.
- `scripts/smoke_local.py` aprovado: banco temporário, cadastro de raiz autorizada/projeto, job SAST com Semgrep real, achado persistido, histórico e exportação SARIF.
- `scripts/backup.py` executado: backup consistente e integridade SQLite verificada.
- Leitura Git e GitHub API confirmadas com autenticação existente; envio em branch de feature autorizado pelo usuário.
- Warning observado: Starlette depreca seu TestClient baseado em httpx nesta versão; não afetou os testes.

## Ambiente reutilizável

O usuário publicou o ambiente e a implementação foi restaurada nesta instância. O novo rascunho não foi alterado nem publicado nesta etapa. A rede atual está irrestrita e aplicada; nenhuma credencial adicional foi solicitada.

Acesso Git e GitHub API confirmado com a autenticação injetada, incluindo permissão de push. Operações de rede e TestClient exigem execução com permissão ampliada neste executor. TLS permaneceu habilitado.

## Pendências para cumprir a especificação completa

1. A suíte externa valida respostas reais das cinco fontes e a consulta OSV por versão. Ampliar validação ponta a ponta de coleta incremental, enriquecimento persistido e SCA em repositórios representativos.
2. Completar paginação/erros por registro e testes de falha parcial de cada conector, métricas CVSS vetoriais OSV e histórico completo de alterações por campo.
3. Pacotes afetados já têm tabela/indexação e filtros básicos avançados. Ainda falta normalizar achados em tabelas próprias, ampliar busca por intervalos de versões, limites máximos de pontuação, data de atualização e otimizar busca textual em grandes bases.
4. O detalhe agora apresenta pacotes, intervalos/correções, métricas e referências navegáveis por fonte. Falta associação a inventários locais e apresentação especializada de CWE/CPE.
5. Completar dashboard histórico, filtros temporais interativos, gráficos EPSS, tecnologias e evolução de achados.
6. Expandir parsers para variantes históricas e resolução de versões; importação SBOM dedicada; inventário e comparação de execuções com cobertura comparável.
7. Expandir regras SAST para categorias solicitadas e validar por linguagem; triagem por achado, comparação de execuções e cancelamento pela UI.
8. Webhook com restrições SSRF, agrupamento/frequência/entrega persistente; integrações opcionais Teams/Slack/SMTP. Apenas notificações locais estão implementadas.
9. Configurações editáveis validadas, retenção, backup/restauração na UI, preferências e tema claro; hoje a configuração efetiva é somente leitura e definida por ambiente.
10. Acessibilidade: foco contido já foi adicionado ao drawer de vulnerabilidades; falta estender a todos os dialogs e auditar WCAG; completar testes de componentes, fluxo E2E de scan e detalhe, estados de API e navegabilidade.
11. Docker, Windows, executável, PostgreSQL e workflows precisam de execução real. Incluir Semgrep nas distribuições compatíveis e não prometer SAST nativo Windows antes de validar.
12. Isolamento mais forte e recursos agregados para código adversarial; autenticação/autorização/TLS para qualquer implantação remota.
13. Conectores oficiais complementares ainda não implementados; não há cobertura prometida para eles.

## Retomada

Leia AGENTS.md e ARCHITECTURE.md. Use o checkout existente; não crie worktree. Execute `bash scripts/start.sh`. Valide GET /api/health e GET /api/dashboard localmente, sem criar preview. Não inclua fixtures no banco operacional. Não reinicie a implementação do zero: os módulos acima já existem e têm testes.

## Falhas corrigidas nesta sessão

- Corrigido tipo React para métricas desconhecidas e referência de tipos de CSS no TypeScript.
- Separados testes Vitest e Playwright para impedir coleta pelo runner errado.
- Reexecução final do navegador após atualizar build/servidor passou; as falhas intermediárias de bundle antigo e reinicialização do servidor não foram tratadas como resultados aprovados.
- Integração real executada nesta etapa; build Docker, execução Windows, PostgreSQL e CI remoto ainda não foram validados.
