param(
    [string]$ShortcutFolder = [Environment]::GetFolderPath("Desktop")
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$PowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Write-Info($Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

function New-HexSOCShortcut {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [string]$Description
    )

    if (!(Test-Path -LiteralPath $ScriptPath)) {
        throw "Shortcut target script not found: $ScriptPath"
    }

    $Shell = New-Object -ComObject WScript.Shell
    $ShortcutPath = Join-Path $ShortcutFolder "$Name.lnk"
    $Shortcut = $Shell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $PowerShell
    $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $Shortcut.WorkingDirectory = $ProjectRoot
    $Shortcut.Description = $Description
    $Shortcut.IconLocation = "$PowerShell,0"
    $Shortcut.Save()

    Write-Success "Created shortcut: $ShortcutPath"
}

try {
    Write-Info "Creating HexSOC AI Agent desktop control buttons"
    Write-Info "Shortcut folder: $ShortcutFolder"

    if (!(Test-Path -LiteralPath $ShortcutFolder)) {
        New-Item -ItemType Directory -Force -Path $ShortcutFolder | Out-Null
    }

    New-HexSOCShortcut `
        -Name "HexSOC Agent - Install Task" `
        -ScriptPath (Join-Path $PSScriptRoot "install_windows_task.ps1") `
        -Description "Install the HexSOC AI Agent scheduled task."

    New-HexSOCShortcut `
        -Name "HexSOC Agent - Start" `
        -ScriptPath (Join-Path $PSScriptRoot "start_agent_task.ps1") `
        -Description "Start the HexSOC AI Agent scheduled task."

    New-HexSOCShortcut `
        -Name "HexSOC Agent - Stop" `
        -ScriptPath (Join-Path $PSScriptRoot "stop_agent_task.ps1") `
        -Description "Stop the HexSOC AI Agent scheduled task."

    New-HexSOCShortcut `
        -Name "HexSOC Agent - Status" `
        -ScriptPath (Join-Path $PSScriptRoot "status_agent_task.ps1") `
        -Description "Show HexSOC AI Agent scheduled task status."

    New-HexSOCShortcut `
        -Name "HexSOC Agent - Uninstall Task" `
        -ScriptPath (Join-Path $PSScriptRoot "uninstall_windows_task.ps1") `
        -Description "Remove the HexSOC AI Agent scheduled task."

    Write-Success "HexSOC AI Agent desktop control buttons are ready."
    Write-Info "No API keys were printed or stored in shortcuts."
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
