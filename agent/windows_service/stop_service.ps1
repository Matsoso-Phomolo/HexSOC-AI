$ErrorActionPreference = "Stop"
$ServiceName = "HexSOCAgent"

function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    Stop-ScheduledTask -TaskName $ServiceName
    Write-Success "Scheduled task '$ServiceName' stopped."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
