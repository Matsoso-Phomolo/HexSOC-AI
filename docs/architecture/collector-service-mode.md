# Collector Service Mode

HexSOC Agent can run persistently on Windows using Task Scheduler. This keeps the collector lightweight while providing enterprise-style startup, restart, stop, and status operations without packaging a Windows service binary.

## Runtime Command

The scheduled task runs from the project root:

```powershell
python agent\hexsoc_agent.py --env production --interval 60 --log-file logs/agent-production.log
```

The task reads production configuration from `agent/config.production.json` or environment variables. API keys are never printed by the scheduler scripts.

## Task Scheduler Strategy

- Default trigger: user logon.
- Optional trigger: system startup.
- Restart on failure: enabled with a bounded retry count.
- Multiple instances: ignored to prevent duplicate collectors.
- Working directory: repository root.
- Log file: `logs/agent-production.log`.

## Operations

- Install: `agent/scripts/install_windows_task.ps1`
- Start: `agent/scripts/start_agent_task.ps1`
- Stop: `agent/scripts/stop_agent_task.ps1`
- Uninstall: `agent/scripts/uninstall_windows_task.ps1`
- Health/status: `python agent\hexsoc_agent.py --env production --state-status`
- Queue status: `python agent\hexsoc_agent.py --env production --queue-status`

## Log Management

The agent rotates its log file when it exceeds 5 MB, keeping one `.1` rotated copy. Logs remain local runtime state and are ignored by git.
