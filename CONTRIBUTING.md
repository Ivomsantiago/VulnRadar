# Contribuição

Use Python 3.12 e Node 24. Instale com `scripts/install.ps1` ou `scripts/install.sh`. Leia `AGENTS.md`, as especificações de produto e o [estado verificável](docs/IMPLEMENTATION_STATUS.md). Preserve KPIs de exposição baseados em projetos, migrações aditivas, triagem e histórico. Novas fontes precisam preservar avaliações e aliases, sem transformar inteligência global em achado local.

## Verificação local em Windows

```powershell
.venv/Scripts/python.exe -m ruff check backend
Push-Location backend
../.venv/Scripts/python.exe -m pytest -q --cov=app --cov-report=json:../docs/review/v4/coverage.json
../.venv/Scripts/python.exe -m mypy
Pop-Location
Push-Location frontend
npm.cmd ci
npm.cmd test
npx.cmd tsc --strict --noEmit
npm.cmd run build
npm.cmd audit --audit-level=low
Pop-Location
.venv/Scripts/python.exe scripts/review_inventory.py
.venv/Scripts/python.exe scripts/generate_sbom.py
```

Instale antes `backend/requirements-dev.txt` no ambiente do backend. Linux usa `.venv/bin/python` e `npm`/`npx`. Mypy é gradual: strict em quatro módulos da fronteira HTTP/acesso; ampliar para os demais módulos novos é pendência explícita. O frontend já usa strict.

Para o navegador, em outro terminal:

```powershell
.venv/Scripts/python.exe scripts/start_test_server.py --mock-osv --port 8004
```

Depois de instalar Chromium com `npx.cmd playwright install chromium`, execute em `frontend`:

```powershell
$env:VULNRADAR_TEST_URL='http://127.0.0.1:8004'
$env:VULNRADAR_SCREENSHOT_DIR='../docs/screenshots/v4/after'
npx.cmd playwright test
```

O launcher usa banco, repositório e chave descartáveis, com OSV fictício identificado. Semgrep é real e precisa estar em `.semgrep-venv`; não ignore o teste para obter sucesso artificial. Nunca use o banco operacional nesse fluxo ou versione cookies em `test-results/auth`.

Integrações públicas reais são opt-in: em `backend`, defina `$env:VULNRADAR_LIVE_TESTS='1'` e execute `../.venv/Scripts/python.exe -m pytest -q tests/integration`. Não confunda mocks de navegador com resposta de fontes reais. Symlinks no Windows exigem os privilégios correspondentes; testes ignorados devem continuar identificados.

Para auditorias, use `pip-audit==2.10.1 -r backend/requirements.txt --no-deps --disable-pip` e Gitleaks com relatório redigido. O requirements contém versões fixadas, mas ainda não hashes de distribuição. SBOM cobre manifests declarados, sem sistema operacional ou ambiente Semgrep opcional. Comandos e saídas reais ficam em `docs/REVIEW_V4.md`.

Use commits por tema no formato `tipo(escopo): descrição`. Não inclua `.env`, dados, bancos, segredos ou screenshots operacionais. Não faça push, publique release ou altere nome/description/topics sem autorização. Licença MIT.
