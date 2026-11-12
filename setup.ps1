# One-shot server setup for verni-server (fresh Windows VPS or this PC).
# ASCII-only on purpose: PowerShell 5.1 reads .ps1 without BOM as ANSI.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File setup.ps1 -ServerHost <IP-or-DNS> [-Task] [-SkipWorker]
#
# -ServerHost  address the phone will reach (goes into cert CN + key endpoint)
# -Task        register a Scheduled Task: autostart at boot as SYSTEM
# -SkipWorker  skip the GitHub artifact download (worker already in place)
$ErrorActionPreference = "Stop"
param(
    [string]$ServerHost = "",
    [switch]$Task,
    [switch]$SkipWorker
)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

function Step($m) { Write-Host "[*] $m" }

# 1. Python
Step "checking python..."
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Step "python not found -- installing via winget"
    winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
    $env:Path = "$env:Path;$env:LOCALAPPDATA\Programs\Python\Python312;C:\Python312"
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Error "python still missing -- reboot or add to PATH manually" }
}

# 2. deps
Step "installing python deps..."
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Error "pip failed" }

# 3. cert + token + key
if (-not (Test-Path ".\.env.server")) {
    if (-not $ServerHost) { Write-Error "-ServerHost <IP-or-DNS> required on first run (no .env.server yet)" }
    Step "generating cert/key/token for $ServerHost..."
    python make_key.py all $ServerHost
    if ($LASTEXITCODE -ne 0) { Write-Error "make_key failed" }
} else {
    Step ".env.server exists -- keeping existing cert/key/token"
}

# 4. worker artifact from GitHub Actions
$exe = Join-Path $here "worker\verni-worker-Win32\iOSAuthSingle.exe"
if (-not (Test-Path $exe)) {
    if ($SkipWorker) {
        Write-Warning "worker exe missing and -SkipWorker set"
    } else {
        Step "downloading worker artifact (latest build-worker run)..."
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if ($gh) {
            $runId = gh run list --repo colossalblend/verni-server --workflow build-worker --status success -L 1 --json databaseId -q '.[0].databaseId'
            if (-not $runId) { Write-Error "no successful build-worker run found" }
            gh run download $runId --repo colossalblend/verni-server --name verni-worker-Win32 -D worker\verni-worker-Win32
            if ($LASTEXITCODE -ne 0) { Write-Error "gh download failed (gh auth login first?)" }
        } else {
            Write-Error "gh CLI not found: install via 'winget install GitHub.cli', run 'gh auth login', then re-run setup.ps1"
        }
    }
} else {
    Step "worker exe already in place"
}

# 5. dsid.txt fallback next to the exe
if (Test-Path ".\dsid.txt") {
    $hits = Get-ChildItem -Recurse -Path worker -Filter iOSAuthSingle.exe -ErrorAction SilentlyContinue
    foreach ($h in $hits) {
        $dst = Join-Path $h.Directory.FullName "dsid.txt"
        if (-not (Test-Path $dst)) { Copy-Item ".\dsid.txt" $dst; Step "copied dsid.txt -> $dst" }
    }
}

# 6. firewall (best effort; needs admin)
try {
    netsh advfirewall firewall show rule name="verni-server 18766" | Out-Null
    if (-not $?) { throw }
    Step "firewall rule already present"
} catch {
    Step "adding firewall rule for 18766 (needs admin; skip if this fails)"
    netsh advfirewall firewall add rule name="verni-server 18766" dir=in action=allow protocol=TCP localport=18766 | Out-Null
}

# 6b. tighten secrets file ACLs (only SYSTEM + Administrators + current user)
foreach ($f in @(".\.env.server", ".\key.pem", ".\verni-key.txt")) {
    if (Test-Path $f) {
        icacls $f /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "$env:USERDOMAIN\$env:USERNAME:F" 2>$null | Out-Null
        Step "ACL tightened: $f"
    }
}

# 7. optional autostart task
if ($Task) {
    Step "registering Scheduled Task 'VerniServer' (autostart at boot, SYSTEM)..."
    $ps = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$here\run_server.ps1`""
    schtasks /Create /F /TN "VerniServer" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR $ps
    if ($LASTEXITCODE -ne 0) { Write-Error "schtasks failed" }
}

# 8. status
Step "done. state:"
Write-Host ("  .env.server : " + (Test-Path ".\.env.server"))
Write-Host ("  verni-key.txt : " + (Test-Path ".\verni-key.txt"))
Write-Host ("  worker exe : " + (Test-Path $exe))
Write-Host ""
Write-Host "Account setup (browser + iTunes + SC Info), in an RDP session:"
Write-Host "  python setup_account.py --email you@example.com"
Write-Host "  (script signs in itself; 2FA you confirm in the window or paste the"
Write-Host "   code here; iTunes is installed and launched automatically; the"
Write-Host "   only possibly manual step is Store -> Authorize in the iTunes"
Write-Host "   window if SC Info files do not appear after first launch)"
Write-Host "Session keepalive (auto re-login if cookies die; 2FA stays manual):"
Write-Host "  python session_keepalive.py --email you@example.com"
Write-Host "Start: .\run_server.ps1   (worker spawns automatically)"
