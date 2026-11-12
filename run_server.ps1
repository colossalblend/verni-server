# Run uvicorn with TLS, token loaded from .env.server (next to this script).
# Supervisor: restarts uvicorn if it dies (Ctrl+C twice stops; set VERNI_NOSUPERVISOR=1 to run once).
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (-not (Test-Path ".\.env.server")) {
    Write-Error "no .env.server found -- run first: python make_key.py all HOSTNAME"
}
Get-Content ".\.env.server" | ForEach-Object {
    if ($_ -match '^VERNI_TOKEN=(.+)$') { $env:VERNI_TOKEN = $matches[1] }
}
if (-not $env:VERNI_TOKEN) { Write-Error "VERNI_TOKEN not loaded" }
if (-not $env:VERNI_WORKER_HOST) { $env:VERNI_WORKER_HOST = "127.0.0.1" }
# iOSAuthSingle listens on fixed TCP 27987 (see main.cpp). Override via env if you patched it.
if (-not $env:VERNI_WORKER_PORT) { $env:VERNI_WORKER_PORT = "27987" }
# Optional: several worker instances for parallel accounts, e.g. "27987,27988,27989"
# (each port = one running iOSAuthSingle.exe; the server spreads sessions across them).

while ($true) {
    python -m uvicorn server:app --host 0.0.0.0 --port 18766 `
        --ssl-certfile "$here\cert.pem" --ssl-keyfile "$here\key.pem" `
        --no-server-header --limit-concurrency 128 --timeout-graceful-shutdown 15 `
        --log-level info
    if ($env:VERNI_NOSUPERVISOR -eq "1") { break }
    $code = $LASTEXITCODE
    if ($code -eq 0) { Write-Host "uvicorn exited cleanly"; break }
    Write-Host "uvicorn exited with code $code -- restarting in 5s"
    Start-Sleep -Seconds 5
}
