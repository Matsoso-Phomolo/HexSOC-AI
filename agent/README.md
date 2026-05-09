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
5. Create a local config file from the example:

```powershell
Copy-Item config.example.json config.json
```

6. Edit `config.json` and set:

```json
{
  "backend_url": "https://hexsoc-ai.onrender.com",
  "collector_api_key": "PUT_COLLECTOR_KEY_HERE",
  "mode": "windows_sysmon_sample",
  "batch_size": 10,
  "auto_detect": true,
  "agent_version": "0.1.0",
  "heartbeat_interval_seconds": 60,
  "send_events_on_interval": false
}
```

`config.json` is ignored by git so real collector keys are not committed.

## Run

Install dependencies:

```powershell
pip install -r requirements.txt
```

Send only a heartbeat:

```powershell
python hexsoc_agent.py --config config.json --heartbeat-only
```

Send the sample Windows/Sysmon telemetry once:

```powershell
python hexsoc_agent.py --config config.json --once
```

Run continuously with heartbeat monitoring:

```powershell
python hexsoc_agent.py --config config.json --interval 60
```

Set `"send_events_on_interval": true` if you want the prototype to send the sample telemetry on each interval.

Use a custom events file:

```powershell
python hexsoc_agent.py --config config.json --once --events-file sample_windows_events.json
```

You can also provide the key through the environment:

```powershell
$env:COLLECTOR_API_KEY = "hexsoc_live_xxxxxxxx_secret"
python hexsoc_agent.py --config config.json --once
```

## Verify

After a successful run:

- The Live Collectors panel should show an updated `last_seen_at`.
- Security events should appear in the dashboard.
- Detection alerts should appear when `auto_detect` is enabled.
- The activity timeline should show collector ingestion activity.

## Safety

Never commit real collector API keys. Rotate or revoke keys from the Live Collectors panel if a key is exposed.
