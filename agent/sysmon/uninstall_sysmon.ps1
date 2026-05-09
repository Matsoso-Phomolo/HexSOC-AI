param(
    [string]$SysmonPath = ""
)

$ErrorActionPreference = "Stop"
if (!$SysmonPath) { $SysmonPath = Join-Path $PSScriptRoot "Sysmon64.exe" }

function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
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
    & $SysmonPath -u
    if ($LASTEXITCODE -ne 0) { throw "Sysmon uninstall exited with code $LASTEXITCODE" }
    Write-Success "Sysmon uninstalled."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
