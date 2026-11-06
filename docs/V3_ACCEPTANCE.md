# V3 — critérios de aceite e evidências

Esta entrega aplica a especificação V3 ao produto local. Não declara cobertura universal de vulnerabilidades nem uso remoto multiusuário.

| Critério | Implementação | Evidência |
| --- | --- | --- |
| Backend/frontend iniciam | FastAPI, Vite, scripts Linux/Windows e migrações explícitas | Build, health e servidor descartável |
| Oito jornadas e ações reais | navigation.ts, main.tsx, abas contextuais, URLs antigas com filtros | completion.spec.ts, navigation.spec.ts |
| Exposição local consistente | Achados SCA/SAST/OCI; inteligência global separada; desconhecido sem análise | test_operations_v2.py, test_v3_completion.py |
| Coleta e monitoramento | NVD/GitHub incrementais, OSV pacote/batch, KEV/EPSS, produto/versão e watchlist | Sete testes de APIs externas; testes de checkpoint, rate limit e alertas |
| SCA preciso nos formatos cobertos | Normalização por ecossistema, versões resolvidas, alias/direto/transitivo, correções restritas ao componente | test_security_scanner.py, test_v3_regressions.py, test_v3_completion.py |
| SAST rastreável | Semgrep real, regra/arquivo/evidência e identidade por código/ocorrência | test_sast.py e jornada combinada do navegador |
| OCI opcional funcional | Trivy/Grype remotos, digest, fonte, inventário, achados, cancelamento e ausência explícita | OCI real validado pelo navegador para ambos os mecanismos; subprocesso cancelado e verificado por PID |
| Evidência/histórico preservados | FindingObservation por execução, FindingState imutável, Activity auditável | Testes de baseline, alteração de estado, resolução e reabertura |
| Remediação persiste | FP/justificativa, responsável, prazo, plano e validade UTC; reabertura de aceite expirado | Regressões/API e Playwright com recarga/fuso de São Paulo |
| Correção/reanálise reais | Alteração dos arquivos da fixture descartável; nova execução de SCA/Semgrep | Dois achados resolvidos; ambos reabertos após restauração da falha, sem novos IDs |
| Relatórios/exportações | Filtros/paginação, mudanças, histórico diário, SLA, JSON/CSV/PDF servidor, SARIF/CycloneDX por scan | Testes de filtros e CSV, PDFs extraídos pelo Poppler, navegador e exports técnicos |
| AppSec da ferramenta | Handles/raízes autorizadas, recusa de links/junctions, limites, sem shell/build dos alvos, React/CSP/HTTP locais e allowlists | Testes de symlink/ancestral, consulta parcial, cancelamento, SSRF/webhook e scanner opcional |
| Dados preservados | Migrações aditivas 0005/0006 e backup consistente SQLite | Banco 0002/0004/0005 com dados; upgrade/downgrade; owner/plano/triagem/evidências preservados |
| UI responsiva/acessível | Temas claro/escuro, teclado, estados vazios/erro/loading, tabelas e oito jornadas | 18 rotas × seis larguras; Axe em páginas operacionais e nos dois temas |
| Documentação condizente | V3_STATUS, ARCHITECTURE, README, SECURITY e catálogo de capturas | Revisão cruzada dos endpoints e limites reais |

## Resultados de validação

- Backend local com fontes externas: **97 aprovados**, incluindo **sete integrações oficiais reais**. Um aviso de depreciação do Starlette TestClient.
- Frontend: **sete aprovados**, TypeScript/build aprovados e **zero vulnerabilidades reportadas pelo npm audit**.
- Playwright: **14 cenários aprovados** no servidor reproduzível; **um cenário OCI real aprovado separadamente**, cobrindo os dois scanners. O teste OCI é explicitamente ignorado no modo padrão.
- Ruff, compileall, pip check e git diff --check aprovados. PDF A4 validado por Poppler com texto extraível.

As verificações remotas de Linux/Windows ficam vinculadas ao commit do PR. Comandos usados:

```bash
cd backend
VULNRADAR_LIVE_TESTS=1 ../.venv/bin/pytest -q
cd ../frontend
npm test
npm run build
npm audit --audit-level=high
```

Navegador usa `scripts/start_test_server.py --mock-osv`, banco temporário e Semgrep real. OSV e CPE dessa suíte são explicitamente fictícios; não substituem as integrações de produção. A validação real OCI usa outro banco descartável e imagem pública:

```bash
VULNRADAR_TEST_URL=http://127.0.0.1:8002 npx playwright test --output=test-results/main
VULNRADAR_TEST_URL=http://127.0.0.1:8003 VULNRADAR_OCI_LIVE_TESTS=1 npx playwright test completion.spec.ts --grep 'OCI real' --output=test-results/oci
```

Não compartilhar a mesma pasta de artefatos entre execuções simultâneas. OCI real é opt-in em CI, exige os binários oficiais e acesso a registros/bases. Os dois mecanismos foram executados localmente sobre `alpine:3.22.0`; o Trivy também foi exercitado com uma distribuição fora de suporte para validar aviso de cobertura.

O aviso de depreciação do Starlette TestClient não é uma falha de teste. A cobertura de regras, ecossistemas, versões condicionais, histórico anterior ao baseline e implantação local está delimitada em V3_STATUS.md. Auditoria automatizada Axe não equivale a certificação humana WCAG.
