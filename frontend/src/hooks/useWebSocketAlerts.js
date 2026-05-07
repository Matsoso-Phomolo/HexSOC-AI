import { useEffect } from "react";

export function useWebSocketAlerts(onMessage) {
  useEffect(() => {
    const socket = new WebSocket("ws://localhost:8000/ws/alerts");

    socket.onmessage = (event) => {
      onMessage?.(JSON.parse(event.data));
    };

    return () => socket.close();
  }, [onMessage]);
}
