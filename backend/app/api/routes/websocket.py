from fastapi import APIRouter, WebSocket

router = APIRouter()


@router.websocket("/alerts")
async def alerts_socket(websocket: WebSocket) -> None:
    """Accept a WebSocket connection for future real-time alert delivery."""
    await websocket.accept()
    await websocket.send_json({"type": "connected", "channel": "alerts"})
    await websocket.close()
