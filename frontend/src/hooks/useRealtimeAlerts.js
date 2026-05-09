import { useEffect, useRef, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:9000";

function buildWebSocketUrl() {
  const url = new URL(API_BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws/alerts";
  url.search = "";
  return url.toString();
}

export function useRealtimeAlerts({ onMessage }) {
  const [status, setStatus] = useState("reconnecting");
  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const messageHandlerRef = useRef(onMessage);

  useEffect(() => {
    messageHandlerRef.current = onMessage;
  }, [onMessage]);

  useEffect(() => {
    let closedByHook = false;

    function connect() {
      setStatus("reconnecting");
      const socket = new WebSocket(buildWebSocketUrl());
      socketRef.current = socket;

      socket.onopen = () => {
        setStatus("connected");
      };

      socket.onmessage = (event) => {
        try {
          const message = normalizeRealtimeMessage(JSON.parse(event.data));
          messageHandlerRef.current?.(message);
        } catch {
          messageHandlerRef.current?.({ type: "message", raw: event.data });
        }
      };

      socket.onerror = () => {
        setStatus("offline");
      };

      socket.onclose = () => {
        if (closedByHook) {
          setStatus("offline");
          return;
        }

        setStatus("reconnecting");
        reconnectTimerRef.current = window.setTimeout(connect, 3000);
      };
    }

    connect();

    return () => {
      closedByHook = true;
      window.clearTimeout(reconnectTimerRef.current);
      socketRef.current?.close();
    };
  }, []);

  return status;
}

function normalizeRealtimeMessage(message) {
  if (message?.payload && typeof message.payload === "object") {
    return {
      ...message.payload,
      type: message.type,
      timestamp: message.timestamp,
      payload: message.payload,
    };
  }
  return {
    ...message,
    timestamp: message?.timestamp ?? new Date().toISOString(),
    payload: Object.fromEntries(Object.entries(message ?? {}).filter(([key]) => !["type", "timestamp"].includes(key))),
  };
}
