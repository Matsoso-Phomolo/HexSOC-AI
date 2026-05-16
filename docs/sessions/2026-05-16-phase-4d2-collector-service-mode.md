# Phase 4D.2 — Collector Service Mode and Auto-Restart

## Date
2026-05-16

## Goal
Make HexSOC Agent operationally persistent on Windows using Task Scheduler and safe runbooks.

## Context
Phase 4D.1 hardened network resilience. The next need is persistent operation without an open terminal.

## Files Changed
- `agent/scripts/install_windows_task.ps1`
- `agent/scripts/uninstall_windows_task.ps1`
- `agent/scripts/start_agent_task.ps1`
- `agent/scripts/stop_agent_task.ps1`
- `agent/hexsoc_agent.py`
- `docs/architecture/collector-service-mode.md`
- `README.md`

## What Changed
- Added Task Scheduler install/start/stop/uninstall scripts.
- Added restart-on-failure task settings.
- Added production log path guidance.
- Added simple agent log rotation at 5 MB.
- Documented state and queue status commands for operators.

## Architecture Impact
The collector remains a lightweight Python endpoint agent while gaining persistent Windows runtime behavior.

## Validation
- Compile checks required.
- Agent and backend unit tests required.

## Production Notes
Use `agent/config.production.json` or environment variables for production backend URL and collector API key. Do not commit real configs or logs.

## Known Limitations
This does not introduce NSSM, a packaged Windows service binary, remote fleet management, or backend-driven policy.

## Next Steps
Run the installer on the Windows endpoint, start the task, and confirm Live Collectors stays online after logout/reboot.
