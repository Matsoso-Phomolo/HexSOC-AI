# ADR-0002 - Windows Task Scheduler Agent Runtime

## Status

Accepted

## Context

The HexSOC Agent needs to run continuously in the background on Windows endpoints. A true Windows service binary or NSSM setup adds packaging complexity before the agent contract is stable.

## Decision

Use Windows Task Scheduler as the first service-style runtime for the HexSOC Agent.

The scheduled task is named `HexSOCAgent` and runs:

```powershell
python agent\hexsoc_agent.py --env production --interval 60 --log-file agent\logs\hexsoc-agent.log
```

## Consequences

This approach avoids requiring an executable packaging pipeline and keeps the Python agent transparent for early enterprise development and debugging.

It is sufficient for early production-style endpoint tests, but future enterprise distribution may require a signed service binary, installer, or managed agent package.

## Alternatives Considered

- NSSM wrapper
- Native Windows Service implementation
- Packaged EXE with service registration
- Manual terminal execution

Task Scheduler was selected first because it is built into Windows and does not require additional runtime tooling.

## Related Files / Phases

- Phase 3B.7 Windows Service Installer
- `agent/windows_service/install_service.ps1`
- `agent/windows_service/README.md`
- `agent/hexsoc_agent.py`
