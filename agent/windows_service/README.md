# HexSOC AI Agent Windows Service

This folder provides a docs-first Windows background service setup using Windows Task Scheduler. It does not package the Python agent into an executable, so it stays transparent and easy to inspect.

Scheduled task:

- Task name: `HexSOCAgent`
- Display name: `HexSOC AI Agent`
- Startup command: `python agent\hexsoc_agent.py --env production --interval 60 --log-file agent\logs\hexsoc-agent.log`
- Working directory: project root
- Log file: `agent\logs\hexsoc-agent.log`

## Prerequisites

Run PowerShell as Administrator when installing or uninstalling the task.

Before installing:

1. Confirm Python is installed and available as `python`.
2. Confirm `agent\config.production.json` exists.
3. Confirm the production collector key is stored in config or environment variables.
4. Run a dry-run:

```powershell
python agent\hexsoc_agent.py --env production --dry-run --show-config
```

The dry-run masks API keys. Do not place raw keys in screenshots or support tickets.

## Install

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\install_service.ps1
```

Optional interval:

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\install_service.ps1 -IntervalSeconds 60
```

## Start

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\start_service.ps1
```

## Stop

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\stop_service.ps1
```

## Status

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\status_service.ps1
```

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\uninstall_service.ps1
```

## Verification

1. Open Task Scheduler.
2. Go to Task Scheduler Library.
3. Confirm `HexSOCAgent` exists.
4. Start the task.
5. Confirm `agent\logs\hexsoc-agent.log` is created.
6. Confirm the HexSOC dashboard shows the collector as online.
7. Stop the task.
8. Uninstall the task when finished testing.

## Security

The scripts never print collector API keys. Real config files and logs are ignored by git.
