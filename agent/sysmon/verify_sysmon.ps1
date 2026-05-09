$ErrorActionPreference = "Stop"
$Channel = "Microsoft-Windows-Sysmon/Operational"

function Write-Info($Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success($Message) { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warn($Message) { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Fail($Message) { Write-Host "[FAILED] $Message" -ForegroundColor Red }

try {
    $Service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if (!$Service) { $Service = Get-Service -Name Sysmon -ErrorAction SilentlyContinue }
    if ($Service) {
        Write-Success "Sysmon service installed: $($Service.Name) ($($Service.Status))"
    }
    else {
        Write-Warn "Sysmon service not found."
    }

    $Log = Get-WinEvent -ListLog $Channel -ErrorAction SilentlyContinue
    if ($Log) {
        Write-Success "Operational channel exists: $Channel"
    }
    else {
        Write-Warn "Operational channel missing: $Channel"
    }

    $Events = @(Get-WinEvent -LogName $Channel -MaxEvents 5 -ErrorAction SilentlyContinue)
    Write-Info "Sample events readable: $($Events.Count)"
    if ($Events.Count -gt 0) {
        Write-Info "Latest EventRecordID: $($Events[0].RecordId)"
    }
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
