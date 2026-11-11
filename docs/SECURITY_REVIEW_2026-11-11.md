# Revisão de segurança e imagens — 11/11/2026

Revisão no checkout `main`, após incorporar os commits locais V4 até `c1ce55d`. Cenário: equipe em servidor privado, workspace compartilhado. Foram examinadas as fronteiras de autenticação/autorização, HTTP, importação, filesystem/processos, integrações, dados, interface, dependências e pipelines. Não houve migração do banco operacional, envio de notificações, execução de scripts dos alvos ou deploy. A reorganização remota das refs foi autorizada separadamente e está em [BRANCHES](BRANCHES.md).

## Achados confirmados e correções

| Achado | Condição e evidência | Correção e regressão |
| --- | --- | --- |
| Média: credenciais em avisos de requirements | Uma opção `--extra-index-url https://fixture:FIXTURE_INDEX_CREDENTIAL@packages.example.test/simple` era copiada integralmente para o aviso persistido. Acesso posterior aos resultados podia revelar o segredo. Reproduzido com credencial fictícia, sem acessar um registro real | `backend/app/services/scanner.py` omite o conteúdo da linha não interpretada. `test_pip_index_credentials_never_appear_in_scan_warnings` falhou antes e passou depois |
| Média: processamento desproporcional de documentos | YAML permitia aliases/merges antes dos limites de componentes; imports aceitavam estrutura profundamente aninhada. Uma demonstração pequena de merges produziu 1, 4, 16 e 64 nós de mapeamento, sem carga de negação de serviço | `input_budget.py` limita profundidade a 32 e estrutura a 200.000 nós/eventos; YAML é inspecionado antes do carregamento e rejeita aliases/merges. JSON/TOML e SARIF/VEX recebem limites estruturais; componentes são limitados dentro do parser. Regressores verificam rejeição, inventário parcial e preservação dos componentes já observados |
| Média: concentração do orçamento de sessões | Uma chave válida podia preencher os slots globais. Reprodução isolada com orçamento reduzido a três sessões fez um login administrativo retornar 429 | Limite padrão de quatro sessões por chave, configurável entre 1 e 32. Novo login revoga a sessão mais antiga da própria identidade; o teto global continua obrigatório. Teste com dois slots por chave confirma espaço para outra identidade |
| Média: destinos externos herdados por fixtures | O entrypoint de teste carregava configurações do ambiente, incluindo destinos de notificações e credenciais de fontes | `scripts/browser_test_app.py` desativa webhook/SMTP e remove tokens NVD/GitHub no processo de teste. Regressão em subprocesso verifica valores fictícios herdados, sem contato externo |
| Baixa: dado pessoal em imagens | Capturas Windows de projetos/configurações e fundo de investigação exibiam o nome pessoal no caminho absoluto | Galeria atual e comparativo V4 recapturados pelo navegador em diretório neutro `Users/Public`, com fixtures explícitas. PNGs inspecionados e sem metadados textuais adicionais. Versões antigas continuam no histórico Git; não foi feita reescrita de histórico |

Manifestos malformados também passaram a gerar cobertura parcial sem descartar componentes observados em outros arquivos. Isso não autoriza resolver achados por ausência. Nenhuma alteração de schema foi necessária nesta rodada.

## Controles e alcance

O inventário atualizado registra 82 módulos e 64 declarações de rota. A regressão percorre as operações API publicadas no OpenAPI: sem autenticação exige 401, e operações proibidas para viewer/analyst exigem 403. Rotas públicas de saúde, prontidão e autenticação são tratadas explicitamente. A matriz é evidência da política atual; não equivale a pentest completo de cada combinação de objeto e regra de negócio. O workspace é compartilhado: não há isolamento entre organizações ou projetos.

Foram reexercitados os testes de TLS/cookies em modo team, negação por padrão, identidade de auditoria, limites HTTP/SSE/operações, erros sem reflexão de segredos, pinagem webhook, proteção de paths/symlinks, snapshot e subprocessos. A renderização de evidências é texto; a suíte inclui fluxos de importação/triagem e critérios axe selecionados. Semgrep examinou o código próprio com as regras locais, sem achados: [artefato](review/v4/application-sast.json). Isso não prova ausência de vulnerabilidades nem cobre todas as classes OWASP.

Referências usadas para os controles: [OWASP API4:2023 — consumo de recursos](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/), [OWASP — prevenção de negação de serviço](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) e [OWASP — sessões](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). O mapeamento orienta a revisão; não constitui declaração de conformidade integral.

## Verificação executada

| Verificação | Resultado |
| --- | --- |
| Backend completo com cobertura | 153 aprovados, 9 skips, 138,10 s; cobertura total 79%. Sete skips são integrações opt-in exercitadas separadamente, dois dependem de privilégio de symlink Windows; um aviso de depreciação TestClient/httpx |
| Integrações públicas reais | 7 aprovados; leitura NVD/GitHub/KEV/EPSS/OSV/CPE, sem notificações |
| Ruff e mypy | Aprovados; strict em cinco módulos, incluindo `input_budget`, não no backend inteiro |
| Frontend Node 24.22.2 | 8 testes aprovados; TypeScript strict e build aprovados |
| Navegador descartável | 19 cenários aprovados, incluindo 18 rotas em seis larguras, fontes alternativas a 390 px, axe, SAST real, recorrência, SARIF/VEX |
| Dependências | pip-audit 2.10.1 e npm audit: zero vulnerabilidades conhecidas; 58 pacotes Python compatíveis |
| Segredos | Gitleaks 8.30.1: 19 commits examinados até `c72c496`, 2,20 MB, zero achados; SARIF temporário com redação 100%. Não comprova ausência de segredos |
| Banco descartável | `alembic check` aprovado; inventário/schema/planos atualizados em `review/v4` |
| Executável Windows | Reconstruído com PyInstaller 6.22.3 da fonte revisada; smoke com banco descartável aprovou health/login/API protegida/ready/frontend. SHA-256 em `review/v4/windows-exe-smoke.json`; interação humana não exercitada |
| Workflows | actionlint 1.7.12 + ShellCheck 0.11.0 aprovados. Resultado remoto e correções ainda locais discriminados em [CI_REVIEW](CI_REVIEW.md) |

## Imagens e reprodução

A [galeria atual](screenshots/readme/README.md) contém oito capturas reais, com viewport desktop/mobile, conta de teste e dados identificados como fixture. O helper `frontend/scripts/capture_docs.mjs` exige loopback e marcador exclusivo do entrypoint descartável antes de autenticar ou criar projeto. Recusa caminhos de perfis pessoais. Nunca apontar esse fluxo para o servidor operacional.

O [comparativo V4](screenshots/v4/README.md) foi recapturado com paths neutros: 108 imagens da base `79eff96` exportada e compilada isoladamente, mais 110 imagens da versão atual. A base exportada recebeu somente o marcador do entrypoint de teste, sem criar outro checkout/worktree. São fixtures novas, portanto diferenças de contagem não medem evolução real de exposição. V2/V3 permanecem identificados como registros históricos. Não houve edição de pixels para ocultar falhas ou produzir evidências.

## Limites de produção

Ainda é necessário homologar o host privado: TLS/proxy/firewall, conta de serviço, backups externos e restauração operacional, reinício e concorrência. Docker não foi executado neste ambiente; PostgreSQL segue experimental. SQLite exige o modelo operacional documentado de um worker. Não há SSO/MFA, isolamento por projeto, sandbox forte para SAST, criptografia transparente do banco ou revisão humana completa de acessibilidade. SAST em equipe permanece bloqueado por padrão.

As pendências de arquitetura, tipagem e tabelas legadas constam em [IMPLEMENTATION_STATUS](IMPLEMENTATION_STATUS.md). Os resultados automatizados não aprovam integralmente produção, não certificam OWASP e não demonstram ausência de vulnerabilidades. Novas correções estão locais na main; a reorganização de branches não publicou esses commits.
