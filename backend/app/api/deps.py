from app.db.database import get_db_session


# Re-export dependency names from a single API-facing module.
get_db = get_db_session
