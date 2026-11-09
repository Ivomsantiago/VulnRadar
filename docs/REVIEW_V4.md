# Revisão V4 — 09/11/2026

Base: `79eff96`, checkout existente, branch `v4/revisao`. Escopo adicional confirmado: equipe em servidor privado, um workspace compartilhado. O V4 completo está **em execução**, não aprovado para produção nesta etapa.

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
| V4-01 / A01,A07 / API1,2,5 | backend/app/main.py:64 | Serviço alcançável por outra pessoa/processo | Leitura e mutação de todo o workspace sem identidade; cabeçalho público não autentica | Alta | Middleware verifica somente Origin e X-VulnRadar-Client; consulta por IDs sem principal | Autenticação e permissões centrais, sessão revogável e auditoria de identidade | pendente |
| V4-02 / A02 / API8 / privacidade | backend/app/main.py:64 | Navegador, cache compartilhado ou erro de validação | Respostas sensíveis cacheáveis, cabeçalhos omitidos em erros; erro Pydantic pode refletir entrada | Média | Early returns antes dos headers; erro padrão inclui input | Fronteira HTTP com headers em todos os caminhos e erros mínimos | pendente |
| V4-03 / A06 / API4,6 | backend/app/main.py:344 | Acesso à API | Consultas externas/exportações simultâneas e sessões SSE sem orçamento por identidade | Média | Limite de jobs cobre scans, não consultas HTTP em andamento | Orçamentos de requisições e streams | pendente |
| V4-04 / A02 / API7 | backend/app/services/notifications.py:30 | DNS de destino permitido comprometido | Verificação DNS e conexão usam resoluções separadas | Média | getaddrinfo seguido de AsyncClient por hostname | Egress externo obrigatório até pinagem de transporte validada | pendente |
| V4-05 / A04 / privacidade | backend/app/services/scanner.py:386 | Scanner instalado e credenciais no ambiente | Subprocesso herda variáveis de ambiente do servidor | Alta | create_subprocess_exec sem env explícito | Ambiente mínimo separado por execução | pendente |
| V4-06 / privacidade | backend/app/services/intelligence.py:315 | SCA/watchlist de software confidencial | Identidade e versão dos pacotes transmitidas ao OSV sem política técnica de bloqueio | Média | Conectores enviam coordenadas ao serviço público | Controle de egress de pacotes no servidor e aviso de finalidade | pendente |
| V4-07 / arquitetura | backend/app/main.py:1, backend/app/operations.py:1 | Manutenção de APIs | Routers concentram regras de negócio e serializam ORM diretamente | Média | Inventário de LOC/rotas e leitura de handlers | Extração gradual e DTOs novos explícitos | pendente |
| V4-08 / operação | backend/app/workers.py:139 | Falha inesperada no agendador/entregador | Task de longa duração pode morrer sem reinício supervisionado | Média | Loops aguardam I/O sem isolamento de toda a iteração | Supervisão com espera limitada e logs mínimos | pendente |

## Ativo, histórico e legado

- Ativo: FastAPI, oito jornadas React, fontes NVD/GitHub/OSV/KEV/EPSS, SCA/SAST, inventário, investigação, triagem, relatórios e notificações webhook.
- Histórico compatível: evidências OCI, normalização dos relatórios anteriores e `/oci` na interface. Endpoint POST OCI responde 410.
- Código morto confirmado: `scripts/install_engines.py` (somente encerra com aviso); não é chamado pelos launchers.
- Documentos V2/V3 e capturas correspondentes são registros históricos. Os módulos com sufixo V2 ainda contêm operações ativas e testes de preservação; não são removidos pelo nome.

## Referências normativas

Revisão orientada pelo [OWASP Top 10:2025](https://top10.owasp.org/2025/), [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/), [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) e [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). São referências de controle e verificação, não certificação automática.
