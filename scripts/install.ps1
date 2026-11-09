$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
py -3.12 -m venv .venv
if ($LASTEXITCODE) { throw 'Falha criando ambiente Python' }
& .venv\Scripts\python.exe -m pip install -r backend/requirements.txt
if ($LASTEXITCODE) { throw 'Falha instalando backend' }
npm --prefix frontend ci
if ($LASTEXITCODE) { throw 'Falha instalando frontend' }
npm --prefix frontend run build
if ($LASTEXITCODE) { throw 'Falha no build frontend' }
& .venv\Scripts\python.exe scripts/migrate.py
if ($LASTEXITCODE) { throw 'Falha nas migrações' }
