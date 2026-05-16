param(
    [string]$TaskName = "HexSOCAgent"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$LogFile = Join-Path $ProjectRoot "logs\agent-production.log"

function Write-Info($Message) { Write-Host $Message -ForegroundColor Cyan }
function Write-Success($Message) { Write-Host $Message -ForegroundColor Green }
function Write-Warn($Message) { Write-Host $Message -ForegroundColor Yellow }
function Write-Fail($Message) { Write-Host $Message -ForegroundColor Red }

try {
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $Info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop

    Write-Info "================================================"
    Write-Info "HEXSOC AI AGENT TASK STATUS"
    Write-Info "================================================"
    Write-Host ("Task name       : {0}" -f $TaskName)
    Write-Host ("State           : {0}" -f $Task.State)
    Write-Host ("Last run        : {0}" -f $Info.LastRunTime)
    Write-Host ("Last result     : {0}" -f $Info.LastTaskResult)
    Write-Host ("Next run        : {0}" -f $Info.NextRunTime)
    Write-Host ("Log file        : {0}" -f $LogFile)

    if (Test-Path -LiteralPath $LogFile) {
        $Log = Get-Item -LiteralPath $LogFile
        Write-Host ("Log size        : {0:N0} bytes" -f $Log.Length)
        Write-Host ("Log updated     : {0}" -f $Log.LastWriteTime)
    }
    else {
        Write-Warn "Log status      : Not created yet"
    }

    if ($Task.State -eq "Running") {
        Write-Success "Status          : RUNNING"
    }
    else {
        Write-Warn "Status          : NOT RUNNING"
    }

    Write-Info "================================================"
}
catch {
    Write-Fail "================================================"
    Write-Fail "HEXSOC AI AGENT TASK STATUS"
    Write-Fail "================================================"
    Write-Fail ("Status          : FAILED")
    Write-Fail ("Reason          : {0}" -f $_.Exception.Message)
    Write-Fail "================================================"
    exit 1
}
