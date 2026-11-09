param([switch]$OpenBrowser)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (Test-Path .semgrep-venv\Scripts\semgrep.exe) { $env:PATH = (Join-Path (Get-Location) '.semgrep-venv\Scripts') + [IO.Path]::PathSeparator + $env:PATH }
if ($OpenBrowser) { Start-Process 'http://127.0.0.1:8000' }
& .venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log
