# HexSOC Agent Prototype

The HexSOC Agent is a lightweight telemetry sender for testing live collector ingestion. It uses collector API keys instead of analyst JWTs, so external scripts can submit Windows/Sysmon events safely.

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
  "send_events_on_interval": true
}
```

Real config files are ignored by git so collector keys are not committed.

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

You can also provide the key through the environment:

```powershell
$env:COLLECTOR_API_KEY = "hexsoc_live_xxxxxxxx_secret"
python hexsoc_agent.py --once
```

## Verify

After a successful run:

- The Live Collectors panel should show an updated `last_seen_at`.
- Security events should appear in the dashboard.
- Detection alerts should appear when `auto_detect` is enabled.
- The activity timeline should show collector ingestion activity.

## Safety

Never commit real collector API keys. Rotate or revoke keys from the Live Collectors panel if a key is exposed.
