# Download + silent-install iTunes 12.10.11 (32-bit) -- the build the FairPlay
# worker links against (last x86 iTunes; 64-bit iTunes.dll has different offsets).
# Official Apple CDN link, taken from the Apple support page for 12.10.11 32-bit.
# ASCII-only on purpose (PS 5.1 no-BOM reads ANSI).
#
# Usage:  powershell -ExecutionPolicy Bypass -File install_itunes.ps1
#
# After install: open iTunes, sign in, Store -> Authorize This Computer.
# SC Info appears in C:\ProgramData\Apple Computer\iTunes\SC Info (machine-wide).
$ErrorActionPreference = "Stop"
$url = "https://secure-appldnld.apple.com/itunes12/001-80042-20210422-E8A351F2-A3B2-11EB-9A8F-CF1B67FC6302/iTunesSetup.exe"
$tmp = Join-Path $env:TEMP "iTunesSetup.exe"

$reg32 = @(
    "HKLM:\SOFTWARE\WOW6432Node\Apple Computer, Inc.\iTunes",
    "HKLM:\SOFTWARE\Apple Computer, Inc.\iTunes"
)
$installed = $false
foreach ($r in $reg32) {
    if (Test-Path $r) { $installed = $true; break }
}
if ($installed) {
    Write-Host "[ok] iTunes already installed (registry found) -- skipping download"
} else {
    Write-Host "[*] downloading iTunesSetup.exe (~177 MB)..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -lt 10MB) { Write-Error "download failed or file too small" }
    Write-Host "[*] installing (passive, no restart)..."
    $p = Start-Process -FilePath $tmp -ArgumentList "/passive","/norestart" -Wait -PassThru
    Write-Host "[*] installer exit code: $($p.ExitCode)"
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { Write-Error "installer exit code $($p.ExitCode) -- run $tmp manually" }
}

# Verify what the worker needs (32-bit registry view)
$ok = @()
foreach ($key in @("HKLM:\SOFTWARE\WOW6432Node\Apple Computer, Inc.\iTunes")) {
    if (Test-Path $key) {
        $dir = (Get-ItemProperty $key).InstallDir
        Write-Host "[ok] iTunes InstallDir: $dir"
        $ok += "itunes"
    }
}
foreach ($key in @(
    "HKLM:\SOFTWARE\WOW6432Node\Apple inc.\Apple Application Support",
    "HKLM:\SOFTWARE\Apple inc.\Apple Application Support"
)) {
    if (Test-Path $key) { $ok += "aas" }
}
foreach ($key in @(
    "HKLM:\SOFTWARE\WOW6432Node\Apple inc.\Apple Mobile Device Support",
    "HKLM:\SOFTWARE\Apple inc.\Apple Mobile Device Support"
)) {
    if (Test-Path $key) { $ok += "amds" }
}
Write-Host "[*] components found: $($ok -join ', ')"
if ($ok -notcontains "itunes") { Write-Warning "iTunes registry not visible -- check install manually" }
Write-Host ""
Write-Host "Next: open iTunes, sign in with your Apple ID, then Store -> Authorize This Computer."
Write-Host "Verify after authorize: C:\ProgramData\Apple Computer\iTunes\SC Info\SC Info.sidb"
