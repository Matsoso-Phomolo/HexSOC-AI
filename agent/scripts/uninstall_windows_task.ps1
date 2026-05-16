$ErrorActionPreference = "Stop"
$TaskName = "HexSOCAgent"

function Write-Info($Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (!$Task) {
        Write-Warn "Scheduled task '$TaskName' is not installed."
        exit 0
    }

    Write-Info "Stopping scheduled task '$TaskName' if running."
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Success "Scheduled task '$TaskName' removed."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
