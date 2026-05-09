$ErrorActionPreference = "Stop"
$ServiceName = "HexSOCAgent"

function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    Start-ScheduledTask -TaskName $ServiceName
    Write-Success "Scheduled task '$ServiceName' started."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
