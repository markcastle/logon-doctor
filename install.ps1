# Logon Doctor installer
#
# Usage (PowerShell, no admin needed to install):
#   irm https://raw.githubusercontent.com/markcastle/logon-doctor/main/install.ps1 | iex
#
# What it does:
#   1. Downloads the latest logon-doctor.exe release (64-bit Windows only)
#   2. Puts it in %LOCALAPPDATA%\logon-doctor
#   3. Adds that folder to your *user* PATH (no admin, no system changes)
#
# Re-run it any time to upgrade. Uninstall = delete the folder and remove it from PATH.

$ErrorActionPreference = 'Stop'

$repo = 'markcastle/logon-doctor'
$dir  = Join-Path $env:LOCALAPPDATA 'logon-doctor'
$url  = "https://github.com/$repo/releases/latest/download/logon-doctor.exe"
$dest = Join-Path $dir 'logon-doctor.exe'

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Logon Doctor needs 64-bit Windows.'
}

# Older PowerShell defaults to TLS 1.0, which GitHub rejects.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host 'Downloading logon-doctor.exe from the latest release...'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing

# Add to user PATH if it isn't there already.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "Added $dir to your user PATH."
}
# Make it work in this session too, not just new windows.
if (($env:Path -split ';') -notcontains $dir) { $env:Path += ";$dir" }

$ver = & $dest --version
Write-Host ''
Write-Host "Installed $ver to $dest"
Write-Host 'For the full picture, open an ELEVATED terminal (Run as administrator) and type: logon-doctor'
