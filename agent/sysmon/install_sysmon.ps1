param(
    [string]$SysmonPath = "",
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if (!$SysmonPath) { $SysmonPath = Join-Path $PSScriptRoot "Sysmon64.exe" }
if (!$ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot "sysmon-config.xml" }

function Write-Info($Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }
function Assert-Admin {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    if (!$Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required."
    }
}

try {
    Assert-Admin
    if (!(Test-Path -LiteralPath $SysmonPath)) { throw "Sysmon64.exe not found: $SysmonPath" }
    if (!(Test-Path -LiteralPath $ConfigPath)) { throw "Sysmon config not found: $ConfigPath" }

    Write-Info "Installing Sysmon for HexSOC AI telemetry"
    Write-Info "Project root: $Root"
    Write-Info "Config     : $ConfigPath"
    & $SysmonPath -accepteula -i $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw "Sysmon installer exited with code $LASTEXITCODE" }
    Write-Success "Sysmon installed and configured."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
