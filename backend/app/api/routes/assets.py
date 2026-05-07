from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import models
from app.schemas.asset import AssetCreate, AssetRead

router = APIRouter()


@router.post("/", response_model=AssetRead, status_code=201, summary="Create asset")
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)) -> models.Asset:
    """Store an enterprise asset inventory record."""
    asset = models.Asset(**payload.dict())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/", response_model=list[AssetRead], summary="List assets")
def list_assets(db: Session = Depends(get_db)) -> list[models.Asset]:
    """Return stored assets ordered by newest first."""
    return db.query(models.Asset).order_by(models.Asset.id.desc()).all()
