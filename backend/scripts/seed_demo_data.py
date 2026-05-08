import json
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.db.database import SessionLocal, init_db
from app.services.demo_seed_service import seed_demo_data


def main() -> None:
    """Seed realistic SOC demo data into the configured database."""
    init_db()
    db = SessionLocal()
    try:
        result = seed_demo_data(db)
        print(json.dumps({"status": "ok", "result": result}, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()
