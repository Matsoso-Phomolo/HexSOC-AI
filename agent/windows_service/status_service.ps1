$ErrorActionPreference = "Stop"
$ServiceName = "HexSOCAgent"

function Write-Info($Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Warn($Message) { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    $Task = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    if (!$Task) {
        Write-Warn "Scheduled task '$ServiceName' is not installed."
        exit 0
    }

    $Info = Get-ScheduledTaskInfo -TaskName $ServiceName
    Write-Info "Task name       : $ServiceName"
    Write-Info "State           : $($Task.State)"
    Write-Info "Last run time   : $($Info.LastRunTime)"
    Write-Info "Last task result: $($Info.LastTaskResult)"
    Write-Info "Next run time   : $($Info.NextRunTime)"
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
