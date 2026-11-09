# VulnRadar

Índice de vulnerabilidades de aplicações, com correlação de advisories, inventário e evidências por análise. Ajuda a investigar, priorizar e acompanhar remediações; ausência de resultados não comprova segurança.

**Execução local por padrão, com chave pessoal obrigatória.** O modo de equipe usa HTTPS e perfis em um workspace compartilhado. Antes de operar no servidor privado, siga o [runbook](docs/RUNBOOK.md) e confira as [pendências verificáveis da V4](docs/IMPLEMENTATION_STATUS.md). Não há isolamento entre organizações, sandbox forte de scanners ou aprovação para exposição pública.

![Fila de trabalho V4, banco descartável de testes](docs/screenshots/v4/after/1440/dashboard.png)

## Instalação local

Requisitos: Python 3.12, Node.js 24 e npm. Em um checkout novo, no PowerShell:

```powershell
.\scripts\install.ps1
.venv\Scripts\python.exe scripts/create_access_key.py admin-01 --role admin --configure-local
.\scripts\start.ps1 -OpenBrowser
```

Guarde a chave exibida em local seguro; ela será solicitada no login em `http://127.0.0.1:8000`. Se `.env` já existir, gere sem `--configure-local` e mescle os hashes das contas. Linux: use `bash scripts/install.sh`, `.venv/bin/python scripts/create_access_key.py admin-01 --role admin --configure-local` e `bash scripts/start.sh`.

## Funcionalidades

| Jornada | Comportamento |
| --- | --- |
| Fila e exposição | Prioridade explicável por achados observados; informação desconhecida quando falta análise; inteligência global separada |
| Inteligência | NVD, GitHub Advisories, OSV, CISA KEV e FIRST EPSS; aliases e avaliações de fontes preservados |
| Aplicações | Inventário SCA por lockfile/SBOM; SAST opcional; importação SARIF 2.1.0 de ferramentas externas |
| Investigação | Evidências por execução, comparação, recorrência e triagem com identidade, justificativa, responsável, prazo e validade |
| VEX | Perfil limitado OpenVEX 0.2 e CycloneDX 1.5 para `not_affected`, vinculado a vulnerabilidade/PURL/versão; aplicação explícita |
| Uso de dependências | Heurística de imports em Python e JS/TS, identificada como observação, sem provar alcançabilidade |
| Monitoramento | Watchlists de pacotes e produtos CPE, agendamento, alertas opcionais por webhook ou SMTP TLS |
| Exportações | JSON/CSV/PDF, SARIF SAST, CycloneDX de inventário e VEX aplicado; CSV protegido contra fórmulas |
| Acesso | Chaves pessoais aleatórias, sessões revogáveis e perfis viewer/analyst/admin; SQLite, um worker |

Grype e Trivy não fazem parte da execução operacional. Evidências antigas permanecem acessíveis em `/oci`; a API de novos scans OCI responde 410. Scans parciais nunca resolvem achados por ausência.

Consultas de pacotes ao OSV e armazenamento de trechos de código começam **desabilitados**. Habilite-os somente após avaliar finalidade e confidencialidade. O resumo de inteligência conserva a maior severidade/CVSS entre avaliações disponíveis e mostra divergências; isso não comprova exploração no projeto.

## Documentação e validação

[Estado e linha do tempo](docs/IMPLEMENTATION_STATUS.md) · [Revisão V4 e achados](docs/REVIEW_V4.md) · [Arquitetura e dados](docs/ARCHITECTURE.md) · [Operação e recuperação](docs/RUNBOOK.md) · [Privacidade](docs/PRIVACY.md) · [Segurança](SECURITY.md) · [Contribuição e testes](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Comparativo visual](docs/screenshots/v4/README.md).

Backend, frontend e navegador foram exercitados em Windows com dados descartáveis; as contagens e os limites estão no estado verificável. Docker, PostgreSQL e os workflows remotos da V4 permanecem **NÃO VALIDADOS**. Licença MIT.
