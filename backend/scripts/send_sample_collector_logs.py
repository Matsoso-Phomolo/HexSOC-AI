"""Send sample Windows/Sysmon telemetry through a HexSOC collector API key."""

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def main() -> None:
    api_key = os.getenv("COLLECTOR_API_KEY")
    backend_url = os.getenv("HEXSOC_BACKEND_URL", "http://127.0.0.1:9000").rstrip("/")

    if not api_key:
        raise SystemExit("COLLECTOR_API_KEY is required")

    sample_path = Path(__file__).resolve().parents[1] / "samples" / "windows_sysmon_sample.json"
    payload = sample_path.read_text(encoding="utf-8")
    request = urllib.request.Request(
        f"{backend_url}/api/collectors/ingest/windows-events/bulk?auto_detect=true",
        data=payload.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-HexSOC-API-Key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"Collector ingest failed: {exc.code} {exc.read().decode('utf-8')}") from exc

    print(
        "Collector ingest complete: "
        f"received={result.get('received')} "
        f"ingested={result.get('ingested')} "
        f"skipped={result.get('skipped')} "
        f"alerts_created={result.get('detection_summary', {}).get('alerts_created', 0)}"
    )


if __name__ == "__main__":
    main()
