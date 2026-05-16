$ErrorActionPreference = "Stop"
$TaskName = "HexSOCAgent"

function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    Stop-ScheduledTask -TaskName $TaskName
    Write-Success "Scheduled task '$TaskName' stopped."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
