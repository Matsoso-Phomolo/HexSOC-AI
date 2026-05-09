$ErrorActionPreference = "Stop"
$ServiceName = "HexSOCAgent"

function Write-Info($Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    $Task = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    if (!$Task) {
        Write-Warn "Scheduled task '$ServiceName' is not installed."
        exit 0
    }

    Write-Info "Stopping scheduled task '$ServiceName' if running."
    Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
    Write-Success "Scheduled task '$ServiceName' removed."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
