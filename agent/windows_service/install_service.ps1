param(
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = "Stop"
$ServiceName = "HexSOCAgent"
$DisplayName = "HexSOC AI Agent"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$AgentScript = Join-Path $ProjectRoot "agent\hexsoc_agent.py"
$ProductionConfig = Join-Path $ProjectRoot "agent\config.production.json"
$LogDir = Join-Path $ProjectRoot "agent\logs"
$LogFile = Join-Path $LogDir "hexsoc-agent.log"

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

    $Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"Set-Location -LiteralPath '$ProjectRoot'; & '$($Python.Source)' agent\hexsoc_agent.py --env production --interval $IntervalSeconds --log-file agent\logs\hexsoc-agent.log`""
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Arguments -WorkingDirectory $ProjectRoot
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 0)
    $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Highest

    try {
        Register-ScheduledTask -TaskName $ServiceName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description $DisplayName -Force | Out-Null
    }
    catch {
        Write-Warn "S4U registration failed. Falling back to interactive user logon."
        $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName $ServiceName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description $DisplayName -Force | Out-Null
    }

    Write-Success "$DisplayName installed as scheduled task '$ServiceName'"
    Write-Info "Log file: $LogFile"
    Write-Warn "API keys are read from config/environment and are never printed by this installer."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
