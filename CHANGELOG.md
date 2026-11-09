# Changelog

Mudanças relevantes seguem a estrutura [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). A V4 ainda não é release publicada.

## [Unreleased] — V4

### Adicionado

- Chaves pessoais com validade, perfis viewer/analyst/admin, cookies revogáveis e auditoria de conta/request-id.
- Modo equipe com HTTPS obrigatório, limites HTTP/SSE, controles de prontidão e recuperação de jobs interrompidos.
- Migração aditiva 0007: exposição declarada, evidências VEX e índices de feed; backup antes do upgrade SQLite oficial.
- SARIF 2.1.0 genérico e perfil de OpenVEX/CycloneDX VEX, com schemas offline e limites.
- Heurística de imports Python/JS/TS e fatores de priorização explicáveis; adaptador SMTP TLS opcional.
- Política de egress OSV/snippets, ambiente mínimo para scanner, controle de grupo/processo e retenção opt-in limitada.
- Tokens visuais, componentes base, login, importação, fila antes dos indicadores e seleção/exportação de achados.
- Workflows com Actions fixadas por SHA, revisão CodeQL/Gitleaks, Dependabot e SBOM declarativo da aplicação.
- Runbook, ADR do banco, política de privacidade, inventário, achados e capturas antes/depois.

### Alterado

- Acesso local também exige chave pessoal; OSV/snippets começam desabilitados e SAST local é bloqueado por padrão em equipe.
- Conexão webhook fixa o IP validado, preservando Host/SNI; logs/erros evitam corpos e credenciais.
- Datas ORM retornam UTC explícito; mapeamento Float foi alinhado às migrações.
- Docker/Compose preparados para TLS, usuário sem root e filesystem somente leitura, ainda sem build/run validado.

### Removido

- Instalador legado sem função operacional `scripts/install_engines.py`. Normalização/evidências OCI e POST 410 preservados.

## V3 e revisão anterior — 2026-11-08

- Inteligência de aplicações, produtos CPE, histórico, SLA, relatórios PDF e correções de correlação/coleta.
- Grype/Trivy retirados da execução operacional, com preservação de evidências antigas.
- Detalhes históricos em `docs/V3_STATUS.md` e `docs/PRODUCTION_REVIEW.md`.

## V2 — 2026-11-06

- Inventários/observações por execução, triagem, jornadas de investigação e migrações aditivas.
- Detalhes históricos em `docs/V2_AUDIT.md`.
