# Phase 4D.2.1 — Silent Background Collector Mode

## Date
2026-05-16

## Goal
Run the Windows scheduled HexSOC Agent silently in the background without opening a visible console window.

## Context
The scheduled task could start the production collector, but launching through `python.exe` could display a console window. Operators need the collector to behave like an enterprise endpoint service while keeping the Task Scheduler approach.

## Files Changed
- `agent/scripts/install_windows_task.ps1`
- `agent/windows_service/install_service.ps1`
- `README.md`
- `agent/README.md`
- `docs/architecture/collector-service-mode.md`

## What Changed
- Added Python runtime resolution that prefers `pythonw.exe` when available.
- Preserved the same production agent arguments and log-file behavior.
- Enabled hidden scheduled task settings.
- Added installer warnings when only `python.exe` is available.

## Architecture Impact
The collector remains a lightweight Python agent managed by Windows Task Scheduler. It now runs silently in normal Windows environments while still logging runtime state to disk.

## Validation
- PowerShell installer scripts parse successfully.
- Python compile checks required.
- Existing backend and agent tests required.

## Production Notes
Reinstall the scheduled task after deploying this update so Task Scheduler picks up the windowless runtime action.

## Known Limitations
Running fully across logout/startup still depends on the selected trigger and Windows account permissions. Startup mode may require elevated installation depending on endpoint policy.

## Next Steps
Run `agent/scripts/install_windows_task.ps1`, start the task, verify no console window appears, and confirm Live Collectors shows the endpoint online.
