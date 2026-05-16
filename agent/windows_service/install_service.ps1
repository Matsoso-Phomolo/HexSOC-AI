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

function Resolve-WindowlessPython {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath
    )

    $PythonDirectory = Split-Path -Parent $PythonPath
    $Pythonw = Join-Path $PythonDirectory "pythonw.exe"

    if (Test-Path -LiteralPath $Pythonw) {
        return $Pythonw
    }

    return $PythonPath
}

try {
    Write-Info "Installing $DisplayName scheduled task"

    if (!(Test-Path -LiteralPath $AgentScript)) {
        throw "Agent script not found: $AgentScript"
    }
    if (!(Test-Path -LiteralPath $ProductionConfig)) {
        throw "Production config not found: $ProductionConfig"
    }

    $Python = Get-Command python -ErrorAction Stop
    $PythonRuntime = Resolve-WindowlessPython -PythonPath $Python.Source
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    $Arguments = "agent\hexsoc_agent.py --env production --interval $IntervalSeconds --log-file agent\logs\hexsoc-agent.log"
    $Action = New-ScheduledTaskAction -Execute $PythonRuntime -Argument $Arguments -WorkingDirectory $ProjectRoot
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 0) -Hidden
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
    Write-Info "Runtime: $PythonRuntime"
    Write-Info "Command args: $Arguments"
    Write-Info "Log file: $LogFile"
    if ((Split-Path -Leaf $PythonRuntime).ToLowerInvariant() -ne "pythonw.exe") {
        Write-Warn "pythonw.exe was not found next to python.exe. The task was installed, but Windows may still show a console window."
    }
    Write-Warn "API keys are read from config/environment and are never printed by this installer."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
