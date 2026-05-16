# Collector Service Mode

HexSOC Agent can run persistently on Windows using Task Scheduler. This keeps the collector lightweight while providing enterprise-style startup, restart, stop, and status operations without packaging a Windows service binary.

## Runtime Command

The scheduled task runs from the project root:

```powershell
python agent\hexsoc_agent.py --env production --interval 60 --log-file logs/agent-production.log
```

The installer resolves `pythonw.exe` beside the active Python runtime when available. This keeps the collector silent and backgrounded while preserving the same agent arguments and log behavior. If `pythonw.exe` is unavailable, the installer falls back to `python.exe` and prints a warning. The task reads production configuration from `agent/config.production.json` or environment variables. API keys are never printed by the scheduler scripts.

## Task Scheduler Strategy

- Default trigger: user logon.
- Optional trigger: system startup.
- Restart on failure: enabled with a bounded retry count.
- Multiple instances: ignored to prevent duplicate collectors.
- Hidden task setting: enabled.
- Working directory: repository root.
- Log file: `logs/agent-production.log`.

## Operations

- Install: `agent/scripts/install_windows_task.ps1`
- Start: `agent/scripts/start_agent_task.ps1`
- Stop: `agent/scripts/stop_agent_task.ps1`
- Status: `agent/scripts/status_agent_task.ps1`
- Uninstall: `agent/scripts/uninstall_windows_task.ps1`
- Desktop controls: `agent/scripts/create_agent_shortcuts.ps1`
- Health/status: `python agent\hexsoc_agent.py --env production --state-status`
- Queue status: `python agent\hexsoc_agent.py --env production --queue-status`

## Desktop Control Buttons

The cloud dashboard cannot launch a local Windows Python process from the browser. Local agent control is handled by Task Scheduler plus Desktop shortcuts. Running `agent/scripts/create_agent_shortcuts.ps1` creates shortcuts for install, start, stop, status, and uninstall operations. The shortcuts do not contain API keys and only invoke local PowerShell scripts.

## Log Management

The agent rotates its log file when it exceeds 5 MB, keeping one `.1` rotated copy. Logs remain local runtime state and are ignored by git.
