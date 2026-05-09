from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.asset import AssetCreate, AssetRead
from app.services.activity_service import add_activity
from app.services.websocket_manager import serialize_activity, websocket_manager

router = APIRouter()


@router.post("/", response_model=AssetRead, status_code=201, summary="Create asset")
async def create_asset(payload: AssetCreate, db: Session = Depends(get_db)) -> models.Asset:
    """Store an enterprise asset inventory record."""
    asset = models.Asset(**payload.dict())
    db.add(asset)
    db.flush()
    activity = add_activity(
        db,
        action="asset_created",
        entity_type="asset",
        entity_id=asset.id,
        message=f"Asset created: {asset.hostname}",
        severity="info",
    )
    db.commit()
    db.refresh(asset)
    db.refresh(activity)
    await websocket_manager.broadcast_activity(
        {"type": "activity_created", "activity": serialize_activity(activity)}
    )
    await websocket_manager.broadcast_dashboard_metrics(db)
    return asset


@router.get("/", response_model=list[AssetRead], summary="List assets")
def list_assets(db: Session = Depends(get_db)) -> list[models.Asset]:
    """Return stored assets ordered by newest first."""
    return db.query(models.Asset).order_by(models.Asset.id.desc()).all()
