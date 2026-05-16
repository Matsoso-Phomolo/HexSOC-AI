$ErrorActionPreference = "Stop"
$TaskName = "HexSOCAgent"

function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    Start-ScheduledTask -TaskName $TaskName
    Write-Success "Scheduled task '$TaskName' started."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
