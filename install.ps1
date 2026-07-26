# skillxray installer for Windows (PowerShell 5.1+).
# Usage:  irm https://raw.githubusercontent.com/aixintan90/skillxray/main/install.ps1 | iex
# Opt out of PATH edits with $env:SKILLXRAY_NO_MODIFY_PATH = "1".
$ErrorActionPreference = "Stop"

$Repo   = "aixintan90/skillxray"
$SrcUrl = "https://raw.githubusercontent.com/$Repo/main/skillxray.py"

$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue) }
if (-not $py) { Write-Error "Python 3.9+ is required but was not found on PATH."; return }
$PyPath = $py.Source

$BinDir = if ($env:SKILLXRAY_INSTALL_DIR) { $env:SKILLXRAY_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }
$LibDir = Join-Path $HOME ".skillxray"
New-Item -ItemType Directory -Force $BinDir | Out-Null
New-Item -ItemType Directory -Force $LibDir | Out-Null

$Dest = Join-Path $LibDir "skillxray.py"
Invoke-WebRequest -Uri $SrcUrl -OutFile $Dest -UseBasicParsing
if (-not (Select-String -Path $Dest -Pattern "skillxray" -Quiet)) {
    Remove-Item $Dest; Write-Error "downloaded file does not look like skillxray."; return
}

# A .cmd shim so `skillxray ...` works from any shell.
$Shim = Join-Path $BinDir "skillxray.cmd"
Set-Content -Encoding ascii $Shim "@`"$PyPath`" `"$Dest`" %*"

Write-Host "installed skillxray -> $Shim"
Write-Host "               source $Dest"

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ';') -notcontains $BinDir) {
    if ($env:SKILLXRAY_NO_MODIFY_PATH -eq "1") {
        Write-Host "note: add $BinDir to your PATH manually."
    } else {
        [Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
        Write-Host "added $BinDir to your user PATH — restart your terminal to pick it up."
    }
}
Write-Host ""
Write-Host "try it:  skillxray scan anthropics/skills"
