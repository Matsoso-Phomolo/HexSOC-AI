# HexSOC Agent Prototype

The HexSOC Agent is a lightweight telemetry sender for testing live collector ingestion. It uses collector API keys instead of analyst JWTs, so external scripts can submit Windows/Sysmon events safely.

## Layout

Canonical environment configuration:

```text
agent/
+-- config.local.json
+-- config.production.json
+-- config.staging.json
|
+-- config.local.example.json
+-- config.production.example.json
+-- config.staging.example.json
|
+-- hexsoc_agent.py
+-- README.md
```

The real `config.*.json` files are local-only and ignored by git. The committed `config.*.example.json` files are safe templates.

## Setup

1. Open HexSOC AI and log in as an admin.
2. Go to **Live Collectors**.
3. Create a collector, for example:
   - Name: `windows-lab-agent`
   - Type: `sysmon`
   - Source label: `lab-windows`
4. Copy the API key when it is shown. It will not be displayed again.
5. Create environment config files from the examples:

```powershell
Copy-Item config.local.example.json config.local.json
Copy-Item config.staging.example.json config.staging.json
Copy-Item config.production.example.json config.production.json
```

6. Edit the target config and set:

```json
{
  "backend_url": "http://127.0.0.1:9000",
  "collector_api_key": "PUT_COLLECTOR_KEY_HERE",
  "mode": "windows_sysmon_sample",
  "batch_size": 10,
  "auto_detect": true,
  "agent_version": "0.1.0",
  "heartbeat_interval_seconds": 60,
  "telemetry_interval_seconds": 60,
  "retry_delay_seconds": 10,
  "offline_queue_enabled": true,
  "offline_queue_path": "data/offline_queue.jsonl",
  "max_retry_attempts": 10,
  "agent_state_path": "data/agent_state.json",
  "deduplicate_events": true,
  "fingerprint_history_limit": 5000,
  "send_events_on_interval": true
}
```

Real config files are ignored by git so collector keys are not committed.

Environment variables can override config files for enterprise deployment:

- `HEXSOC_BACKEND_URL`
- `HEXSOC_API_KEY`
- `HEXSOC_AGENT_NAME`
- `HEXSOC_ENV`

The agent prints `CONFIG SOURCE: FILE`, `CONFIG SOURCE: MIXED`, or `CONFIG SOURCE: ENVIRONMENT_VARIABLES` at startup. API keys are always masked in logs and support output.

## Environments

If no `--config` is supplied, the agent defaults to local mode and loads `config.local.json`.

```powershell
python hexsoc_agent.py --env local --interval 60
python hexsoc_agent.py --env staging --interval 60
python hexsoc_agent.py --env production --interval 60
```

Config resolution:

- `--env local` loads `config.local.json`
- `--env staging` loads `config.staging.json`
- `--env production` loads `config.production.json`

Explicit config paths remain supported:

```powershell
python hexsoc_agent.py --config config.json --once
```

The startup banner prints `ENVIRONMENT: LOCAL`, `ENVIRONMENT: STAGING`, or `ENVIRONMENT: PRODUCTION`. The agent warns if production points at localhost or local points at a public backend.

Production mode enforces safer defaults:

- Production cannot use `localhost` or `127.0.0.1`.
- Production backend URLs must use `https`.
- Local mode warns if it points at a public backend.
- `.env` files are loaded only in local mode; production mode warns if an agent `.env` file exists.

## Run

Install dependencies:

```powershell
pip install -r requirements.txt
```

Send only a heartbeat:

```powershell
python hexsoc_agent.py --heartbeat-only
```

Send the sample Windows/Sysmon telemetry once:

```powershell
python hexsoc_agent.py --once
```

Run continuously with heartbeat and telemetry:

```powershell
python hexsoc_agent.py --interval 60
```

Continuous mode runs until `Ctrl+C` and repeats:

1. Send heartbeat.
2. Ingest Windows/Sysmon telemetry batches.
3. Send post-ingestion heartbeat.
4. Sleep for the configured interval.

Heartbeat-only service mode:

```powershell
python hexsoc_agent.py --heartbeat-loop --interval 60
```

Telemetry-only service mode:

```powershell
python hexsoc_agent.py --telemetry-only --interval 60
```

Temporary network failures are logged and retried on the next cycle instead of stopping the agent.

Use a custom events file:

```powershell
python hexsoc_agent.py --once --events-file sample_windows_events.json
```

You can also provide runtime settings through environment variables. Environment variables override JSON config values.

```powershell
$env:HEXSOC_BACKEND_URL = "https://hexsoc-ai.onrender.com"
$env:HEXSOC_API_KEY = "hexsoc_live_xxxxxxxx_secret"
$env:HEXSOC_AGENT_NAME = "WIN-PROD-ENDPOINT-01"
$env:HEXSOC_ENV = "production"
python hexsoc_agent.py --once
```

CMD examples:

```cmd
set HEXSOC_BACKEND_URL=https://hexsoc-ai.onrender.com
set HEXSOC_API_KEY=hexsoc_live_xxxxxxxx_secret
set HEXSOC_AGENT_NAME=WIN-PROD-ENDPOINT-01
set HEXSOC_ENV=production
python hexsoc_agent.py --once
```

`COLLECTOR_API_KEY` is still accepted as a legacy fallback when `HEXSOC_API_KEY` is not set.

Validate configuration without sending telemetry:

```powershell
python hexsoc_agent.py --env production --dry-run
```

Print the active runtime config with secrets masked:

```powershell
python hexsoc_agent.py --show-config --dry-run
```

For local development, optional `agent/.env` values are supported when `python-dotenv` is installed. Do not commit `.env` files or real collector keys.

## Offline Queue

When telemetry ingestion fails because HexSOC AI is unreachable, the agent stores the failed ingestion payload locally and retries it later. Heartbeats are not queued.

Default queue files:

- `agent/data/offline_queue.jsonl`
- `agent/data/dead_letter_queue.jsonl`

Each queued line contains the endpoint, payload, retry count, and last error. Collector API keys are never stored in queue records.

Queue settings:

```json
{
  "offline_queue_enabled": true,
  "offline_queue_path": "data/offline_queue.jsonl",
  "max_retry_attempts": 10
}
```

Check queue status:

```powershell
python hexsoc_agent.py --queue-status
```

Flush queued telemetry manually:

```powershell
python hexsoc_agent.py --flush-queue
```

Clear queue files:

```powershell
python hexsoc_agent.py --clear-queue
python hexsoc_agent.py --clear-queue --yes
```

If an item exceeds `max_retry_attempts`, it moves to the dead-letter queue. Inspect dead-letter records during outage troubleshooting, then clear them after deciding whether to replay or discard them.

During backend outages:

1. Keep the agent running if possible.
2. Confirm queue growth with `--queue-status`.
3. Restore backend/network connectivity.
4. Run `--flush-queue`, or let the continuous loop flush automatically before sending new telemetry.

## Event Cursor And Duplicate Prevention

The agent stores event fingerprints in `agent/data/agent_state.json` so repeated service-loop cycles do not resend the same telemetry sample.

State settings:

```json
{
  "agent_state_path": "data/agent_state.json",
  "deduplicate_events": true,
  "fingerprint_history_limit": 5000
}
```

The fingerprint uses stable event fields:

- `timestamp`
- `event_type`
- `source`
- `source_ip`
- `destination_ip`
- `username`
- `hostname`
- `raw_message`

Collector API keys are never stored in state.

Check state:

```powershell
python hexsoc_agent.py --state-status
```

Reset state:

```powershell
python hexsoc_agent.py --reset-state
python hexsoc_agent.py --reset-state --yes
```

Resetting state can cause previously sent sample events to be sent again, which may create duplicate alerts. Use it only for testing or controlled replay.

## Real Windows Event Log Mode

Set the agent mode to `windows_event_log` to collect live Windows telemetry instead of replaying `sample_windows_events.json`.

```json
{
  "mode": "windows_event_log",
  "windows_event_channels": [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational"
  ],
  "windows_event_batch_size": 50,
  "windows_event_max_per_cycle": 200,
  "windows_event_start_position": "latest"
}
```

Start position:

- `latest`: first run records the current highest EventRecordID and sends nothing.
- `beginning`: first run reads from the oldest available events up to the configured max.
- `recent`: first run reads the most recent events, defaulting to 50.

Cursor commands:

```powershell
python hexsoc_agent.py --env production --windows-cursor-status
python hexsoc_agent.py --env production --reset-windows-cursors
python hexsoc_agent.py --env production --reset-windows-cursors --yes
python hexsoc_agent.py --env production --windows-events-once --dry-run
python hexsoc_agent.py --env production --windows-events-once --dry-run --windows-debug
python hexsoc_agent.py --env production --windows-events-once
python hexsoc_agent.py --env production --validate-windows-channel Security
python hexsoc_agent.py --env production --validate-windows-channel System
```

Permissions and dependencies:

- Install optional Windows dependency with `pip install pywin32`.
- Security log access may require Administrator privileges.
- Sysmon events require Sysmon installed and the `Microsoft-Windows-Sysmon/Operational` channel present.
- Missing channels warn and do not crash the service loop.
- Non-Windows hosts print a clear unsupported message and keep the agent safe.

Troubleshooting:

- If Security returns access errors, run PowerShell or the scheduled task with Administrator privileges.
- If Sysmon returns a missing channel error, confirm Sysmon is installed and visible in Event Viewer.
- If Windows returns `EvtQuery` invalid handle errors, run `--validate-windows-channel Security` and `--windows-debug` to print the channel, XPath query, flags, event count, and first record ID.
- The reader uses pywin32's supported `EvtQuery(channel, flags, query)` signature with `EvtQueryChannelPath` plus forward or reverse direction flags.
- Event Viewer permissions and audit policy can affect whether events are visible to the agent user.

## Verify

After a successful run:

- The Live Collectors panel should show an updated `last_seen_at`.
- Security events should appear in the dashboard.
- Detection alerts should appear when `auto_detect` is enabled.
- The activity timeline should show collector ingestion activity.

## Safety

Never commit real collector API keys. Rotate or revoke keys from the Live Collectors panel if a key is exposed.

## Windows Background Service

HexSOC Agent can run as a Windows startup task through Task Scheduler.
The scheduled task uses `pythonw.exe` when available, allowing the collector to run silently in the background without opening a terminal window.

Preferred current control scripts live in `agent\scripts`. They run the production agent through the `HexSOCAgent` scheduled task:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\install_windows_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\start_agent_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\stop_agent_task.ps1
powershell -ExecutionPolicy Bypass -File agent\scripts\status_agent_task.ps1
```

To create double-click Desktop buttons for local operations:

```powershell
powershell -ExecutionPolicy Bypass -File agent\scripts\create_agent_shortcuts.ps1
```

The browser dashboard cannot safely execute local Windows commands. Use these Desktop shortcuts when you want manual control without repeatedly opening a terminal.

Install:

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\install_service.ps1
```

Start:

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\start_service.ps1
```

Stop:

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\stop_service.ps1
```

Status:

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\status_service.ps1
```

Uninstall:

```powershell
powershell -ExecutionPolicy Bypass -File agent\windows_service\uninstall_service.ps1
```

The scheduled task writes runtime logs to `agent\logs\hexsoc-agent.log`. Logs are ignored by git and must not contain API keys.
