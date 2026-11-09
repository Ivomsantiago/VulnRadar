# Estado verificável — 09/11/2026

Branch `v4/revisao`, base `79eff96`. Trabalho no checkout existente, sem push, sem migração do banco operacional e sem notificação externa. O escopo confirmado é **equipe em servidor privado, workspace compartilhado**. A V4 adiciona controles para esse cenário, mas **o aceite integral de produção ainda não está concluído**.

## Linha do tempo

| Etapa | Resultado e referência |
| --- | --- |
| V2 — 06/11 | Inventário/observações, triagem, jornadas e testes históricos em [V2_AUDIT](V2_AUDIT.md) e [PRODUCT_SPEC_V2](PRODUCT_SPEC_V2.md) |
| V3 — 07/11 | Produtos CPE, remediação/histórico/PDF e jornadas em [V3_STATUS](V3_STATUS.md), [V3_ACCEPTANCE](V3_ACCEPTANCE.md), [V3_AUDIT](V3_AUDIT.md) |
| Revisão — 08/11 | Execução Grype/Trivy descontinuada, correlação e limites revisados em [PRODUCTION_REVIEW](PRODUCTION_REVIEW.md) |
| V4 — 09/11 | Acesso pessoal/perfis, fronteira HTTP, privacidade, recuperação, migração 0007, SARIF/VEX, heurística, SMTP, revisão visual/CI/docs; evidência atual em [REVIEW_V4](REVIEW_V4.md) |

Documentos V2/V3 são registros históricos; suas limitações/contagens não substituem esta página. Não houve renomeação ou mudança de description/topics remotos.

## Executado nesta revisão

| Verificação | Resultado observado |
| --- | --- |
| Backend completo | `pytest -q --cov=app --cov-report=json:../docs/review/v4/coverage.json`: **143 aprovados, 9 ignorados**, 196,02 s, cobertura total **78%** por módulo no artefato; aviso de depreciação TestClient/httpx |
| Integrações públicas reais | `VULNRADAR_LIVE_TESTS=1 pytest -q tests/integration -rs`: **7 aprovados**, NVD/GitHub/KEV/EPSS/OSV e CPE NVD; somente leitura pública |
| Ruff | `python -m ruff check backend` e `python -m ruff check scripts --config backend/pyproject.toml`: aprovados |
| Mypy gradual | `cd backend; python -m mypy`: aprovado em **4 módulos**, strict; não implica tipagem estrita do backend inteiro |
| Frontend | `npm test`: **8 aprovados**; `tsc --strict --noEmit` e `npm run build`: aprovados |
| Dependências | `pip-audit==2.10.1 -r backend/requirements.txt --no-deps --disable-pip`: nenhuma vulnerabilidade conhecida; `uv pip check`: 58 pacotes compatíveis; `npm audit --audit-level=low`: zero vulnerabilidades |
| Dados | Upgrade fixture V2 com triagem/histórico preservados, repetibilidade e backup/wrapper aprovados; `scripts/review_inventory.py`: `alembic check` aprovado, schema e EXPLAIN salvos |
| SAST Windows nativo | Semgrep 1.184.0 real em ambiente separado; teste de regras/snapshot/encerramento aprovado; sem execução de código do alvo |
| Navegador | Primeira execução V4: **18 aprovados** em 4,7 min; repetição final: **18 aprovados em 3,4 min**. Inclui 18 rotas × seis larguras, axe e fluxos operacionais |
| Empacotamento Windows | PyInstaller 6.22.3 onedir compilou em destino novo; smoke descartável final confirmou health/login/API protegida/ready/frontend. Artefato com SHA-256 do binário; sem interação humana do executável |
| Segredos | Gitleaks 8.30.1, relatório redigido: zero achados nos 14 commits examinados até `418b06f`, 1,80 MB. Ausência de achados não comprova ausência de segredos |

Os nove skips do backend padrão são sete integrações opt-in (exercitadas separadamente acima) e dois cenários de symlink sem privilégio Windows. Não foram convertidos em aprovações. Node executado localmente: 26.13.0; Node 24 é o alvo dos workflows, ainda sem execução remota V4.

## Pendências de implementação

- **Arquitetura parcial:** falta concluir extração de regras/consultas dos routers antigos, camada de repositórios e DTOs explícitos para todos os retornos legados. Inventário de módulos/funções grandes disponível.
- **Tipagem parcial:** strict nos quatro módulos de fronteira; ampliar para todos os novos módulos e código legado.
- **Banco:** enums/CHECKs de tabelas legadas não foram adicionados por reconstrução destrutiva; JSON de evidência permanece. Há validação nas entradas novas e índices aditivos, sem alegar normalização integral.
- **UI parcial:** tokens e superfícies globais, fila de trabalho, login, importação, fatores, seleção/exportação e atalhos nas tabelas principais implementados; nem toda tabela legada migrou ao componente base. Não há avaliação humana completa de acessibilidade.
- **Privacidade:** sem exclusão/anonimização retroativa de auditoria ou criptografia transparente do banco; requer política administrativa/infraestrutura. Sem SSO/MFA ou isolamento por projeto/organização.

## NÃO VALIDADO

| Item | Motivo e próximo critério |
| --- | --- |
| Docker build/run | `docker compose build` foi tentado; comando docker ausente. Executar no host com daemon, conferir volumes/read-only/TLS/healthcheck e opção SAST |
| PostgreSQL | Nenhum servidor/driver/suíte específica exercitado; permanece experimental conforme ADR |
| CI V4 remoto e CodeQL/Gitleaks Actions | Workflows/SHA/permissões preparados; não houve push nem execução remota. Verificar também disponibilidade de CodeQL no repositório privado |
| Servidor privado real | Sem implantação, certificado/PKI/firewall/conta de serviço, backup externo, carga e reinício do gerenciador homologados |
| SMTP/webhook reais | Contratos testados com mocks; nenhum destino/credencial autorizado para envio. Pinagem Host/SNI testada em mock, sem handshake TLS real do webhook |
| Sandbox forte | Não implementada; SAST bloqueado em team por padrão. Controles de processo/snapshot não isolam filesystem/kernel/rede |
| Executável interativo | Smoke HTTP do binário foi executado; interação humana/navegador a partir dele e instalação em máquina limpa não foram exercitados |
| Acessibilidade completa | Axe cobre critérios selecionados e fluxos; falta leitor de tela/avaliação humana WCAG e auditoria completa de contraste |
| Carga de produção/restauração operacional | EXPLAIN e testes descartáveis não substituem benchmark concorrente ou ensaio de recuperação no servidor |
| Supply chain integral | Pins e SBOM declarativo disponíveis; hashes de todos os wheels, SBOM de OS/ambiente opcional e assinatura de artefatos não implementados |

O [runbook](RUNBOOK.md), a [arquitetura](ARCHITECTURE.md), a [privacidade](PRIVACY.md) e o [comparativo visual](screenshots/v4/README.md) descrevem operação e limites. Não interpretar esta revisão como certificação ou prova de ausência de vulnerabilidades.
