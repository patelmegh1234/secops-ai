"use client";

/**
 * React hook for connecting to the backend WebSocket feed.
 * Auto-reconnects on disconnect with exponential backoff.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import type { WsEvent } from "./types";

const WS_BASE =
  process.env.NEXT_PUBLIC_WS_URL?.replace("http", "ws") ||
  "ws://localhost:8000";

interface UseWebSocketOptions {
  onMessage?: (event: WsEvent) => void;
  enabled?: boolean;
}

interface WebSocketState {
  connected: boolean;
  lastEvent: WsEvent | null;
  reconnectCount: number;
}

export function useRealtimeFeed(options: UseWebSocketOptions = {}) {
  const { onMessage, enabled = true } = options;
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectCountRef = useRef(0);
  const mountedRef = useRef(true);

  const [state, setState] = useState<WebSocketState>({
    connected: false,
    lastEvent: null,
    reconnectCount: 0,
  });

  const connect = useCallback(() => {
    if (!enabled || !mountedRef.current) return;

    try {
      const ws = new WebSocket(`${WS_BASE}/ws/feed`);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        reconnectCountRef.current = 0;
        setState((prev) => ({ ...prev, connected: true, reconnectCount: 0 }));
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const data: WsEvent = JSON.parse(event.data);
          if (data.type === "ping") return; // heartbeat

          setState((prev) => ({ ...prev, lastEvent: data }));
          onMessage?.(data);
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        setState((prev) => ({ ...prev, connected: false }));

        // Exponential backoff: 1s, 2s, 4s, 8s, max 30s
        const delay = Math.min(
          1000 * 2 ** reconnectCountRef.current,
          30_000
        );
        reconnectCountRef.current += 1;

        reconnectTimeoutRef.current = setTimeout(() => {
          if (mountedRef.current) {
            setState((prev) => ({
              ...prev,
              reconnectCount: reconnectCountRef.current,
            }));
            connect();
          }
        }, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      // WebSocket not available (SSR) — ignore
    }
  }, [enabled, onMessage]);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return state;
}
