param(
    [ValidateSet("Logon", "Startup")]
    [string]$TriggerType = "Logon",
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = "Stop"
$TaskName = "HexSOCAgent"
$DisplayName = "HexSOC AI Agent"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$AgentScript = Join-Path $ProjectRoot "agent\hexsoc_agent.py"
$ProductionConfig = Join-Path $ProjectRoot "agent\config.production.json"
$LogDir = Join-Path $ProjectRoot "logs"
$LogFile = Join-Path $LogDir "agent-production.log"

function Write-Info($Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    Write-Info "Installing $DisplayName scheduled task"

    if (!(Test-Path -LiteralPath $AgentScript)) {
        throw "Agent script not found: $AgentScript"
    }
    if (!(Test-Path -LiteralPath $ProductionConfig)) {
        throw "Production config not found: $ProductionConfig"
    }

    $Python = Get-Command python -ErrorAction Stop
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    $AgentArgs = "agent\hexsoc_agent.py --env production --interval $IntervalSeconds --log-file logs/agent-production.log"
    $Action = New-ScheduledTaskAction -Execute $Python.Source -Argument $AgentArgs -WorkingDirectory $ProjectRoot
    $Trigger = if ($TriggerType -eq "Startup") {
        New-ScheduledTaskTrigger -AtStartup
    }
    else {
        New-ScheduledTaskTrigger -AtLogOn
    }
    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Days 0) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -MultipleInstances IgnoreNew

    $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description $DisplayName -Force | Out-Null

    Write-Success "$DisplayName installed as scheduled task '$TaskName'"
    Write-Info "Trigger       : $TriggerType"
    Write-Info "Command       : $($Python.Source) $AgentArgs"
    Write-Info "Working dir   : $ProjectRoot"
    Write-Info "Log file      : $LogFile"
    Write-Warn "No API keys were printed. Production config/environment supplies collector secrets."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
