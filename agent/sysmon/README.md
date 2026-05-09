# Sysmon Deployment for HexSOC AI

Sysmon provides high-value Windows endpoint telemetry for HexSOC AI, including process creation, network connections, DNS queries, file creation, registry activity, and process access.

## Official Download

Download Sysmon from Microsoft Sysinternals:

<https://learn.microsoft.com/sysinternals/downloads/sysmon>

Use `Sysmon64.exe` on modern 64-bit Windows endpoints.

## Requirements

- Windows endpoint with Administrator privileges.
- PowerShell running as Administrator.
- `Sysmon64.exe` copied into `agent\sysmon\` or passed to the installer with `-SysmonPath`.
- HexSOC Agent installed and configured.

## Install

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File agent\sysmon\install_sysmon.ps1
```

With explicit Sysmon binary path:

```powershell
powershell -ExecutionPolicy Bypass -File agent\sysmon\install_sysmon.ps1 -SysmonPath C:\Tools\Sysmon64.exe
```

The installer runs:

```powershell
Sysmon64.exe -accepteula -i agent\sysmon\sysmon-config.xml
```

## Verify

```powershell
powershell -ExecutionPolicy Bypass -File agent\sysmon\verify_sysmon.ps1
python agent\hexsoc_agent.py --env production --validate-sysmon
python agent\hexsoc_agent.py --env production --validate-windows-channel Microsoft-Windows-Sysmon/Operational
```

You should see the `Microsoft-Windows-Sysmon/Operational` channel and sample records if Sysmon is generating events.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File agent\sysmon\uninstall_sysmon.ps1
```

This runs:

```powershell
Sysmon64.exe -u
```

## Troubleshooting

- Missing Sysmon channel: confirm Sysmon is installed and check Event Viewer under `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.
- Execution policy errors: run with `-ExecutionPolicy Bypass` or update local execution policy according to your endpoint policy.
- Admin permissions: installation, uninstall, and Security/Sysmon log access may require Administrator privileges.
- Service verification: run `Get-Service Sysmon64` or `sc.exe query Sysmon64`.
- No events: generate activity such as launching a process, DNS lookup, or network connection, then re-run validation.
