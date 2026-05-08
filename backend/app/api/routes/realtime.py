"""Real-time WebSocket routes for SOC dashboard updates."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.websocket_manager import websocket_manager

router = APIRouter()


@router.websocket("/ws/alerts")
async def alerts_stream(websocket: WebSocket) -> None:
    """Keep a live alert and activity stream open for dashboard clients."""
    await websocket_manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
    except Exception:
        websocket_manager.disconnect(websocket)
