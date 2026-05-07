from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="List detections")
def list_detections() -> dict[str, list]:
    """Return detection definitions once rule management is implemented."""
    return {"items": []}
