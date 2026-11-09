# Revisão V4 — 09/11/2026

Base: `79eff96`, checkout existente, branch `v4/revisao`. Escopo adicional confirmado: equipe em servidor privado, um workspace compartilhado. A revisão entrega controles e funcionalidades verificadas, mas o **aceite integral da missão V4 e a homologação de produção permanecem pendentes**. Não houve push, deploy, alteração do banco operacional ou envio de notificações reais.

## Linha de base, antes de alterar código

| Comando | Resultado |
| --- | --- |
| `cd backend; ../.venv/Scripts/python.exe -m pytest -q -rs` | 99 aprovados, 10 ignorados; um aviso do TestClient |
| `.venv/Scripts/python.exe -m ruff check backend` | All checks passed |
| `cd frontend; npm.cmd test` | 7 aprovados |
| `cd frontend; npm.cmd run build` | TypeScript + Vite aprovados |
| `cd frontend; npx.cmd tsc --noEmit` | Aprovado, sem saída |
| `npx.cmd tsc --strict --noEmit -p tsconfig.app.json` | Comando de diagnóstico incorreto: arquivo não existe; projeto usa tsconfig.json com strict já habilitado |
| `npx.cmd tsc --strict --noEmit` | Aprovado no tsconfig.json real |
| `VULNRADAR_SCREENSHOT_DIR=../docs/screenshots/v4/before; npx playwright test` | 13 aprovados, 2 falhos: operações combinadas aguardam Semgrep ausente; teste de recorrência usa separador POSIX no caminho Windows |
| `.venv/Scripts/python.exe scripts/review_inventory.py` | 56 módulos; 52 declarações de rota; 12 funções acima de 60 linhas. Schema e inventário em docs/review/v4 |
| `alembic check` em banco descartável migrado | Falhou: ORM infere Double para CVSS/EPSS, migrações usam Float; correção do mapeamento prevista, sem alterar dados |

Capturas antes: 18 rotas (incluindo legado `/oci`) × seis larguras em `docs/screenshots/v4/before`. A suíte completa não ficou verde na linha de base; as duas falhas não são escondidas por skips novos.

Ignorados: sete integrações externas opt-in, Semgrep não instalado, dois testes de symlink sem privilégio do Windows. Nenhum deles é declarado validado pela execução padrão.

## Achados antes das correções

| Identificação | Local (arquivo:linha na base) | Pré-condições | Impacto | Severidade | Evidência | Correção | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V4-01 / acesso e autenticação / API2,5 | backend/app/main.py:64 | Serviço alcançável por outra pessoa/processo | Leitura e mutação de todo o workspace sem identidade; cabeçalho público não autentica | Alta | Middleware da base verifica somente Origin e X-VulnRadar-Client | `access.py:59,70,112` e `http_security.py:33`: chave aleatória, perfis, sessão revogável; regressões `test_access_v4.py` | corrigido no workspace compartilhado; isolamento por projeto/organização não implementado |
| V4-02 / configuração / API8 / privacidade | backend/app/main.py:64 | Navegador, cache compartilhado ou erro de validação | Respostas sensíveis cacheáveis, cabeçalhos omitidos em erros; validação reflete entrada | Média | Early returns da base precedem headers; erro padrão inclui input | `http_security.py:90` e handler de validação; regressões de 401/403/415/422/500 e timeout | corrigido |
| V4-03 / consumo de recursos / API4,6 | backend/app/main.py:344 | Acesso à API | Consultas/exportações simultâneas e SSE sem orçamento por identidade | Média | Limite de jobs da base não cobre consultas HTTP | `access.py:43`, `http_security.py:33`, `main.py:557`: orçamento por conta, operações caras e streams; regressões HTTP/SSE | corrigido no processo único; carga real NÃO VALIDADA |
| V4-04 / SSRF / API7 | backend/app/services/notifications.py:30 | DNS de destino autorizado comprometido | Verificação DNS e conexão usam resoluções separadas | Média | getaddrinfo seguido de conexão por hostname na base | `notifications.py:32`: IP validado fixado na conexão, Host/SNI original e trust_env=False; teste verifica contrato | corrigido em transporte simulado; handshake do webhook real NÃO VALIDADO |
| V4-05 / desenho seguro / privacidade | backend/app/services/scanner.py:386 | Scanner instalado e credenciais no ambiente | Subprocesso herda variáveis do servidor | Alta | create_subprocess_exec sem env explícito na base | `privacy.py:12`: allowlist mínima, HOME temporário; regressão de NVD/GitHub/AWS/Semgrep; SAST bloqueado por padrão em team | corrigido; sandbox forte continua externo |
| V4-06 / privacidade | backend/app/services/intelligence.py:315 | SCA/watchlist de software confidencial | Pacotes enviados ao OSV sem bloqueio técnico | Média | Conectores enviam coordenadas ao serviço público | `privacy.py:7`: opt-in antes de cache/batch/query; regressão de bloqueio e UI/guia de finalidade | corrigido |
| V4-07 / arquitetura | backend/app/main.py:1, backend/app/operations.py:1 | Manutenção de APIs | Routers concentram regras e retornos ORM | Média | Inventário e handlers grandes ainda presentes | Novo router fino `imports.py`, schemas Project/Scan; demais handlers e repositórios ainda precisam de extração | pendente, correção parcial |
| V4-08 / tratamento de falhas | backend/app/workers.py:139 | Exceção no agendador/entregador | Task de longa duração pode morrer sem supervisão | Média | Loops da base sem isolamento completo | `workers.py:22` e `services/recovery.py:6`: supervisão e recuperação; regressões de falha/cancelamento/reinício | corrigido nos cenários testados |

## Ativo, histórico e legado

- Ativo: FastAPI, oito jornadas React, fontes NVD/GitHub/OSV/KEV/EPSS, SCA/SAST opcional, SARIF/VEX, inventário, investigação, triagem, relatórios e webhook/SMTP opcionais.
- Histórico compatível: evidências OCI, normalização dos relatórios anteriores e `/oci` na interface. Endpoint POST OCI responde 410.
- Código morto confirmado e removido: `scripts/install_engines.py` (somente encerrava com aviso); não era chamado pelos launchers. Grype/Trivy não foram reintroduzidos; referências a seus formatos ficam apenas na compatibilidade histórica.
- Documentos V2/V3 e capturas correspondentes são registros históricos. Os módulos com sufixo V2 ainda contêm operações ativas e testes de preservação; não são removidos pelo nome.

## Pendências verificadas e limites de revisão

| Identificação | Local (arquivo:linha) | Pré-condições | Impacto | Severidade | Evidência | Correção | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V4-09 / integridade de domínio | backend/app/db.py:34,164 | Escrita fora dos serviços/validação | Enums legados podem aceitar valores fora do domínio no SQLite | Média | Schema não contém CHECKs de severidade/triagem/fonte | Planejar migração com validação dos valores existentes; não reconstruir/destruir dados nesta entrega | pendente |
| V4-10 / tipagem | backend/pyproject.toml:19 | Mudança nos módulos novos fora da fronteira | Erros de contrato não cobertos por strict | Baixa | Mypy lista quatro arquivos; novos serviços não estão todos incluídos | Ampliar strict por módulo com contratos de sessão/evidência tipados | pendente |
| V4-11 / UI | frontend/src/Overview.tsx:1, frontend/src/style.css:1 | Uso das jornadas legadas | Painéis vazios, copy e tabelas ainda inconsistentes com o desenho alvo integral | Baixa | Capturas antes/depois e inventário dos componentes | Completar composição das tabelas e revisão editorial de gráficos/estados vazios | pendente, correção parcial |
| V4-12 / operação | compose.yaml:1, .github/workflows/security.yml:1 | Implantação/build/CI | Configuração preparada sem execução no ambiente destino | Não classificada como vulnerabilidade comprovada | Docker ausente, sem push remoto, sem PKI/SMTP de homologação | Executar Docker/CI e ensaio de operação do runbook | NÃO VALIDADO |

### Superfícies auditadas

Leitura de Host/Origin/CSRF, autenticação/perfis, limites/corpo/SSE, raízes e snapshots, ambiente/processos do scanner, webhook/SMTP, UI/links, exports, aliases/fontes e migrações. O [inventário de API](review/v4/api-inventory.json) registra as 64 declarações com arquivo/linha e política estática de cada perfil. O teste central cobre negação de IDs/rotas sem identidade, acesso funcional e tentativas de elevar perfil; não é uma auditoria exaustiva de cada objeto/campo em cada endpoint.

Não existe multi-tenancy: compartilhar acesso aos objetos do workspace é uma decisão de produto explicitada, não uma alegação de implementação BOLA entre organizações. Raízes continuam autorizadas no servidor; chaves não ampliam permissões do filesystem. Windows/POSIX são fronteiras distintas; dois testes de symlink seguem ignorados por falta de privilégio Windows.

Regressões adicionais disponíveis nos arquivos `test_api.py`, `test_production_review.py`, `test_security_scanner.py`, `test_sast.py`, `test_notifications.py`, `test_access_v4.py`, `test_privacy_v4.py`, `test_process_guard_v4.py`, `test_recovery_v4.py`, `test_source_validation_v4.py`, `test_sarif_v4.py`, `test_vex_usage_v4.py`, `test_smtp_v4.py`, `test_retention_v4.py` e `test_backup_v4.py`. Cobertura e testes não implicam ausência de falhas.

## Entrega por fase

| Fase | Implementado e observado | Limites |
| --- | --- | --- |
| 1 — base | Commit `b8d276f`, testes antes, inventário/schema, 108 capturas | Duas falhas iniciais de navegador registradas; baseline não era verde |
| 2 — arquitetura | Fronteira HTTP/acesso extraída, DI de sessão, schemas Project/Scan, recuperação/supervisão, request-id e health/ready; ADR SQLite | Extração de routers/repositórios e strict integral pendentes |
| 3 — dados | 0007 aditiva, índices com EXPLAIN, ORM/migrações alinhados, UTC explícito, backup e retenção limitada, limites/validação de fontes | CHECKs de enums/normalização completa e carga real pendentes |
| 4 — segurança | Perfis/sessões, limites, privacidade, ambiente do scanner, IP fixado no webhook, cabeçalhos/erros, auditoria de dependências/segredos | Sandbox/host/TLS real e revisão de todos os objetos/campos não comprovados |
| 5 — funcionalidades | SARIF genérico, VEX limitado, heurística Python/JS/TS, fatores de prioridade, identidade de auditoria e SMTP TLS | VEX não é suporte irrestrito a todos os perfis; SMTP/webhook sem envio real |
| 6 — design | Tokens, fila primeiro, superfícies/densidade, login/importação, tabelas principais, 108 capturas depois e fluxos axe | Migração integral das tabelas, revisão de todos os gráficos e WCAG humana pendentes |
| 7 — entrega | SHA de Actions verificados, jobs de segurança, Dependabot, SBOM com 263 componentes declarados; Windows build/smoke | CI remoto, Node 24, Docker e SBOM de OS/Semgrep NÃO VALIDADOS |
| 8 — documentação | README, SECURITY, CONTRIBUTING, arquitetura/ERD/fluxos, privacidade/runbook/changelog, linha do tempo e cinco alternativas consultadas | Sem renomeação ou alterações remotas; homologação operacional pendente |

As fases foram sobrepostas: não há oito snapshots independentes de suíte completa, um por fase. Os resultados abaixo registram a base, checkpoints efetivamente executados e a validação integrada final, sem atribuir comandos a momentos em que não ocorreram.

## Validação executada

Windows 11, Python 3.12.16, Node 26.13.0, Semgrep 1.184.0 separado, PyInstaller 6.22.3. Node 24 é configuração dos workflows, não versão executada localmente.

| Comando/contexto | Saída resumida |
| --- | --- |
| Backend após acesso/privacidade | 115 aprovados, 10 ignorados; cobertura 76% |
| Backend após SARIF/VEX/SMTP | 125 aprovados, 9 ignorados; cobertura 76%; Semgrep real aprovado |
| Backend integrado antes das quatro regressões finais | 139 aprovados, 9 ignorados, 189,40 s; cobertura 77% |
| Backend final | **143 aprovados, 9 ignorados, 196,02 s; cobertura 78,20%**; regressões de erro/SSE/priorização aprovadas |
| `cd backend; python -m mypy` | Success: no issues found in 4 source files |
| `python -m ruff check backend` | All checks passed |
| `python -m ruff check scripts --config backend/pyproject.toml` | All checks passed |
| `VULNRADAR_LIVE_TESTS=1 pytest -q tests/integration -rs` | 7 aprovados em 6,79 s; fontes públicas reais, sem mensagens externas |
| `npm.cmd test` | 8 testes aprovados |
| `npx.cmd tsc --strict --noEmit`; `npm.cmd run build` | Aprovados; TypeScript/Vite produziram build |
| `start_test_server.py --mock-osv --port 8004`; Playwright | 18 aprovados em 3,4 min; 18 rotas × seis larguras, sem overflow global/erros API nas navegações verificadas; axe zero violações nos critérios/cenários selecionados |
| `scripts/review_inventory.py` | 81 módulos, 64 declarações de rota, 12 funções >60 linhas; alembic check exit=0; schema/planos/árvore/política de rotas nos artefatos |
| `scripts/generate_sbom.py` | 263 componentes declarados; schema CycloneDX 1.5 validado em teste |
| pip-audit 2.10.1, requirements fixado, `--no-deps --disable-pip` | No known vulnerabilities found; aviso recomenda hashes completos |
| `uv pip check --python .venv/Scripts/python.exe` | 58 pacotes compatíveis |
| `npm.cmd audit --audit-level=low` | found 0 vulnerabilities |
| PyInstaller onedir com regras/schemas/frontend/Alembic | Build aprovado em `dist/v4-review-final`; aviso de módulo opcional sqlalchemy.ext.asyncio sem greenlet, não usado pelo backend síncrono |
| `scripts/smoke_windows_exe.py dist/v4-review-final/VulnRadar/VulnRadar.exe` | Health/login/ready/frontend 200, API sem credencial 401, workspace autenticado vazio; banco temporário e sem abrir navegador |
| `docker compose build` | Comando docker não encontrado; NÃO VALIDADO |

Parsing YAML local dos workflows e checagem de referências de Actions por SHA de 40 caracteres aprovados. Todos os links locais nos documentos principais/revisão/runbook/privacidade/comparativo foram verificados. Há 108 capturas por rota/largura no depois, mais duas capturas de fluxos de evidência/resultados em 1440 px; o antes tem 108.

Tentativas de diagnóstico não aprovadas também são registradas: `python -m pip_audit`/`pip check` no venv criado por uv falharam por ausência desses módulos; auditoria executada depois via `uv tool run --from pip-audit==2.10.1` e compatibilidade por `uv pip check`. Rebuild PyInstaller sobre a pasta anterior falhou por permissão em diretório OneDrive; novo destino de build vazio passou, sem remover dados operacionais.

Gitleaks 8.30.1 oficial com checksum verificado, comando `gitleaks git --redact=100 --report-format json --report-path docs/review/v4/gitleaks.json`: zero achados nos **14 commits até 418b06f**, 1,80 MB examinados; relatório redigido em `review/v4/gitleaks.json`. `.dockerignore` exclui também certificados/segredos, projetos montados, ambientes e builds do contexto. O teste padrão ignora sete integrações opt-in e dois cenários de symlink; as sete integrações foram executadas separadamente. Um aviso de depreciação TestClient/httpx permanece.

## Aceite e decisões

O requisito de aceite integral ainda não está atendido por causa das pendências de arquitetura/tipagem/UI e das validações externas explicitadas. SQLite foi adotado como suporte oficial na ADR; migrar para PostgreSQL requer nova evidência. Removido somente o instalador morto; evidências/normalizadores OCI preservados. Não houve mudança de nome: [cinco alternativas e consultas](NAMING.md), description/topics são sugestões sem aplicação. A escolha/renomeação depende do usuário; não bloqueia as correções autorizadas.

Reprodução completa em [CONTRIBUTING](../CONTRIBUTING.md); configuração e recuperação em [RUNBOOK](RUNBOOK.md); [comparativo visual](screenshots/v4/README.md). Backups, certificados e fixtures não foram colocados no banco operacional.

## Referências normativas

Revisão orientada pelo [OWASP Top 10:2025](https://top10.owasp.org/2025/), [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/), [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) e [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). São referências de controle e verificação, não certificação automática.
