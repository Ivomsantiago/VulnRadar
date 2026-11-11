# Estado verificável — 11/11/2026

Trabalho sempre na **main**, no checkout existente. Escopo confirmado: **equipe em servidor privado, workspace compartilhado**. A reorganização remota autorizada deixou main/dev/homologue e preservou as pontas anteriores; não publicou as correções locais na main. Não houve migração do banco operacional ou notificação externa. **O aceite integral de produção ainda não está concluído.** Ver [branches](BRANCHES.md) e [revisão de segurança e imagens](SECURITY_REVIEW_2026-11-11.md).

Atualização de CI em 11/11: [workflows revisados](CI_REVIEW.md). Logs remotos confirmaram falha de layout a 390 px e, em outra execução, DNS na instalação de pacotes Ubuntu 26.04. Layout corrigido e testado; runner localmente fixado em Ubuntu 24.04 com tentativas limitadas de instalação. Security analysis em `c1ce55d` passou remotamente. Os ajustes atuais ainda precisam ser publicados e executados no runner.

## Linha do tempo

| Etapa | Resultado e referência |
| --- | --- |
| V2 — 06/11 | Inventário/observações, triagem, jornadas e testes históricos em [V2_AUDIT](V2_AUDIT.md) e [PRODUCT_SPEC_V2](PRODUCT_SPEC_V2.md) |
| V3 — 07/11 | Produtos CPE, remediação/histórico/PDF e jornadas em [V3_STATUS](V3_STATUS.md), [V3_ACCEPTANCE](V3_ACCEPTANCE.md), [V3_AUDIT](V3_AUDIT.md) |
| Revisão — 08/11 | Execução Grype/Trivy descontinuada, correlação e limites revisados em [PRODUCTION_REVIEW](PRODUCTION_REVIEW.md) |
| V4 — 09/11 | Acesso pessoal/perfis, fronteira HTTP, privacidade, recuperação, migração 0007, SARIF/VEX, heurística, SMTP, revisão visual/CI/docs; evidência atual em [REVIEW_V4](REVIEW_V4.md) |
| Revisão — 11/11 | Limites estruturais e de sessões por chave, privacidade de avisos, isolamento de destinos das fixtures, novas imagens e branches main/dev/homologue em [SECURITY_REVIEW_2026-11-11](SECURITY_REVIEW_2026-11-11.md) |

Documentos V2/V3 são registros históricos; suas limitações/contagens não substituem esta página. Não houve renomeação ou mudança de description/topics remotos.

## Executado nesta revisão

| Verificação | Resultado observado |
| --- | --- |
| Backend completo | `pytest -q --cov=app --cov-report=json:../docs/review/v4/coverage.json`: **153 aprovados, 9 ignorados**, 138,10 s, cobertura total **79%** por módulo no artefato; aviso de depreciação TestClient/httpx |
| Integrações públicas reais | `VULNRADAR_LIVE_TESTS=1 pytest -q tests/integration -rs`: **7 aprovados**, NVD/GitHub/KEV/EPSS/OSV e CPE NVD; somente leitura pública |
| Ruff | `python -m ruff check backend` e `python -m ruff check scripts --config backend/pyproject.toml`: aprovados |
| Mypy gradual | `cd backend; python -m mypy`: aprovado em **5 módulos**, strict; não implica tipagem estrita do backend inteiro |
| Frontend | `npm test`: **8 aprovados**; `tsc --strict --noEmit` e `npm run build`: aprovados, inclusive na repetição com Node **24.22.2** da revisão de CI |
| Dependências | `pip-audit==2.10.1 -r backend/requirements.txt --no-deps --disable-pip`: nenhuma vulnerabilidade conhecida; `uv pip check`: 58 pacotes compatíveis; `npm audit --audit-level=low`: zero vulnerabilidades |
| Dados | Upgrade fixture V2 com triagem/histórico preservados, repetibilidade e backup/wrapper aprovados; `scripts/review_inventory.py`: `alembic check` aprovado, schema e EXPLAIN salvos |
| SAST Windows nativo | Semgrep 1.184.0 real em ambiente separado; teste de regras/snapshot/encerramento aprovado; sem execução de código do alvo |
| Navegador | Revisão de 11/11: **19 aprovados**, incluindo fontes alternativas a 390 px, 18 rotas × seis larguras, axe e fluxos operacionais. Capturas recapturadas em workspace descartável com path neutro |
| Empacotamento Windows | Reconstruído em 11/11 da fonte revisada, PyInstaller 6.22.3 onedir em destino novo; smoke descartável confirmou health/login/API protegida/ready/frontend. Artefato com SHA-256 do binário; sem interação humana do executável |
| Segredos | Gitleaks 8.30.1, relatório SARIF redigido: zero achados nos 19 commits examinados até `c72c496`, 2,20 MB, em 11/11. Ausência de achados não comprova ausência de segredos |

Os nove skips do backend padrão são sete integrações opt-in (exercitadas separadamente acima) e dois cenários de symlink sem privilégio Windows. Não foram convertidos em aprovações. A revisão inicial usou Node 26.13.0; a revisão atual exercitou Node **24.22.2** localmente. Não confundir a aprovação remota de Security analysis no commit anterior com aprovação dos ajustes atuais.

## Pendências de implementação

- **Arquitetura parcial:** falta concluir extração de regras/consultas dos routers antigos, camada de repositórios e DTOs explícitos para todos os retornos legados. Inventário de módulos/funções grandes disponível.
- **Tipagem parcial:** strict nos cinco módulos configurados; ampliar para o restante do backend.
- **Banco:** enums/CHECKs de tabelas legadas não foram adicionados por reconstrução destrutiva; JSON de evidência permanece. Há validação nas entradas novas e índices aditivos, sem alegar normalização integral.
- **UI parcial:** tokens e superfícies globais, fila de trabalho, login, importação, fatores, seleção/exportação e atalhos nas tabelas principais implementados; nem toda tabela legada migrou ao componente base. Não há avaliação humana completa de acessibilidade.
- **Privacidade:** sem exclusão/anonimização retroativa de auditoria ou criptografia transparente do banco; requer política administrativa/infraestrutura. Sem SSO/MFA ou isolamento por projeto/organização.

## NÃO VALIDADO

| Item | Motivo e próximo critério |
| --- | --- |
| Docker build/run | `docker compose build` foi tentado; comando docker ausente. Executar no host com daemon, conferir volumes/read-only/TLS/healthcheck e opção SAST |
| PostgreSQL | Nenhum servidor/driver/suíte específica exercitado; permanece experimental conforme ADR |
| CI da revisão atual | Security analysis passou em `c1ce55d`; Validate registrou falhas distintas de UI e infraestrutura. Correções de 11/11 aprovadas localmente; confirmar todos os jobs após publicação autorizada |
| Servidor privado real | Sem implantação, certificado/PKI/firewall/conta de serviço, backup externo, carga e reinício do gerenciador homologados |
| SMTP/webhook reais | Contratos testados com mocks; nenhum destino/credencial autorizado para envio. Pinagem Host/SNI testada em mock, sem handshake TLS real do webhook |
| Sandbox forte | Não implementada; SAST bloqueado em team por padrão. Controles de processo/snapshot não isolam filesystem/kernel/rede |
| Executável interativo | Smoke HTTP do binário foi executado; interação humana/navegador a partir dele e instalação em máquina limpa não foram exercitados |
| Acessibilidade completa | Axe cobre critérios selecionados e fluxos; falta leitor de tela/avaliação humana WCAG e auditoria completa de contraste |
| Carga de produção/restauração operacional | EXPLAIN e testes descartáveis não substituem benchmark concorrente ou ensaio de recuperação no servidor |
| Supply chain integral | Pins e SBOM declarativo disponíveis; hashes de todos os wheels, SBOM de OS/ambiente opcional e assinatura de artefatos não implementados |

O [runbook](RUNBOOK.md), a [arquitetura](ARCHITECTURE.md), a [privacidade](PRIVACY.md) e o [comparativo visual](screenshots/v4/README.md) descrevem operação e limites. Não interpretar esta revisão como certificação ou prova de ausência de vulnerabilidades.
