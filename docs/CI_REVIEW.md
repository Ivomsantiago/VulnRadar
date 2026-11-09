# Revisão dos workflows — 09/11/2026

Escopo: `.github/workflows/{ci,security,windows}.yml`, no checkout `v4/revisao`. Nenhum push, dispatch ou alteração remota foi realizado. Não houve falha pública recente reproduzida: a consulta de Actions confirmou [Validate](https://github.com/Ivomsantiago/VulnRadar/actions/runs/42631293204) e [Windows build](https://github.com/Ivomsantiago/VulnRadar/actions/runs/42631293236) aprovados no commit remoto `79eff96`. Isso não valida os workflows V4 locais.

## Ajustes

| Problema observado | Correção e verificação |
| --- | --- |
| Actions de primeira parte ainda usavam runtime Node 20 | Atualizadas para versões com Node 24 e SHA de commit verificado, mantendo Python 3.12/Node 24 da aplicação |
| Pin de CodeQL/Gitleaks usava objeto de tag anotada | CodeQL v4 fixado no commit desreferenciado; Gitleaks usa CLI 8.30.1 com arquivo e SHA-256 fixados. Objetos de tag resolvem no endpoint de archive, mas não são commits; não se atribui a eles uma falha remota não observada |
| CodeQL v3 próximo da depreciação | CodeQL v4, categorias por linguagem e fail-fast desabilitado para preservar diagnóstico de ambas as linguagens |
| Loop de readiness tinha variável não usada e diagnóstico limitado | Prazo explícito, verificação de processo vivo e `/api/ready`, log em falha e encerramento por trap; actionlint + ShellCheck aprovados |
| Workflow Windows não instalava Semgrep e ignorava o teste real | Instalação separada/pinada, teste real de SAST, Ruff, frontend unitário/strict e smoke do executável com banco descartável |
| SBOM era gerado depois dos testes que podem validá-lo | Geração antecipada nas duas plataformas |
| Ausência de lint dos próprios workflows | Job independente executa actionlint 1.7.12, com download e checksum fixados |
| Execuções antigas e artefatos podiam acumular | Concurrency por workflow/ref, timeout por job, retenção de sete dias e upload restrito às evidências atuais |

O scanner de segredos continua bloqueante: Gitleaks percorre histórico completo, retorna erro se encontrar segredos e produz relatório SARIF com redação 100%. O CLI elimina a dependência do runtime Node 20 da action anterior. Não há `continue-on-error`, supressão de testes para obter verde ou redução da análise CodeQL.

Permissões: `contents: read` por padrão, `security-events: write` somente no job CodeQL; checkout não persiste credencial Git. Não há `pull_request_target`, envio de mensagens ou publicação de artefatos/release fora do mecanismo de evidências dos workflows.

## Validação local

- actionlint **1.7.12** com ShellCheck **0.11.0**: sem diagnósticos após correção do loop. Os binários Windows foram obtidos das releases oficiais e seus checksums conferidos.
- Seis referências únicas de Actions verificadas nas APIs oficiais de commit e no `action.yml`: todas apontam para commits e runtime `node24`. [Registro](review/v4/actions-validation.json).
- Archives Linux de actionlint/Gitleaks baixados e SHA-256 comparado ao valor fixado nos workflows. Não foram executados neste host Windows.
- Backend: `python -m pytest -q -rs` em `backend`: **143 aprovados, 9 ignorados**, 133,01 s. Os nove skips são sete integrações públicas opt-in e dois cenários de symlink sem privilégio Windows. Semgrep real foi executado.
- `python -m mypy` em `backend`: aprovado nos quatro módulos configurados. `python -m ruff check backend scripts --config backend/pyproject.toml`: aprovado.
- Frontend usando Node **24.22.2**, archive oficial com SHA-256 verificado: **8 testes aprovados**, `npx tsc --strict --noEmit` e `npm run build` aprovados.
- Navegador com Node **24.22.2**: **18 cenários aprovados** em servidor descartável `scripts/start_test_server.py --mock-osv --port 8006`, incluindo seis larguras, axe, scan Semgrep real, resolução/recorrência, SARIF e VEX. Capturas desta repetição ficaram no diretório temporário, sem substituir as capturas versionadas da V4.
- Gitleaks CLI **8.30.1**: 15 commits examinados, sem segredos detectados; relatório SARIF redigido gerado e lido com sucesso. Isso verifica o comando e formato adotados pelo job; não equivale a ausência comprovada de segredos.
- `python scripts/smoke_windows_exe.py dist/v4-review-final/VulnRadar/VulnRadar.exe`: aprovado, com banco/conta temporários, API sem credencial 401 e health/login/ready/frontend 200. Binário existente da mesma fonte da V4, sem reconstrução nesta correção de YAML.

**NÃO VALIDADO remotamente:** execução integral dos workflows V4 em `ubuntu-latest`/`windows-latest`, upload dos artefatos pelo runner e análise/upload CodeQL. Exigem publicar os commits ou executar os workflows já publicados; a autorização vigente não permite push automático. Lint e comandos locais não são apresentados como sucesso remoto.

Referências oficiais: [depreciação CodeQL v3](https://github.blog/changelog/2025-10-28-upcoming-deprecation-of-codeql-action-v3/), [actionlint](https://github.com/rhysd/actionlint), [Gitleaks CLI](https://github.com/gitleaks/gitleaks). Os scripts e artefatos da revisão preservam o banco operacional.
