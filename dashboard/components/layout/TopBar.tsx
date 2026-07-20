"use client";

import { useEffect, useState } from "react";
import { Wifi, WifiOff, Bell, FlaskConical } from "lucide-react";
import { useRealtimeFeed } from "@/lib/websocket";
import { clsx } from "clsx";

const IS_DEMO = !process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_DEMO_MODE === "true";

export function TopBar() {
  const [currentTime, setCurrentTime] = useState<string>("");
  const [notificationCount, setNotificationCount] = useState(0);

  const { connected, lastEvent, reconnectCount } = useRealtimeFeed({
    onMessage: (event) => {
      if (event.type === "vulnerability_update") {
        setNotificationCount((n) => n + 1);
      }
    },
    enabled: !IS_DEMO,
  });

  useEffect(() => {
    const tick = () =>
      setCurrentTime(
        new Date().toLocaleTimeString("en-US", {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })
      );
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 bg-bg-tertiary border-b border-border-subtle flex items-center justify-between px-6 flex-shrink-0 glass">
      {/* Left: breadcrumb / title */}
      <div className="flex items-center gap-3">
        <span className="text-sm font-mono text-text-muted hidden sm:block">
          secops-ai
        </span>
        <span className="text-text-muted hidden sm:block">/</span>
        <span className="text-sm font-mono text-text-primary">
          incident-command-center
        </span>
      </div>

      {/* Right: status indicators */}
      <div className="flex items-center gap-4">
        {/* Real-time clock */}
        <div className="font-mono text-xs text-text-muted tabular-nums hidden sm:block">
          {currentTime}
          <span className="animate-blink ml-0.5 text-accent-cyan">|</span>
        </div>

        {/* Last event (live mode only) */}
        {!IS_DEMO && lastEvent && lastEvent.type === "vulnerability_update" && (
          <div className="flex items-center gap-1.5 animate-slide-in">
            <span className="status-dot active" />
            <span className="text-xs font-mono text-accent-emerald max-w-[200px] truncate">
              {lastEvent.severity}: {lastEvent.title?.slice(0, 30)}
            </span>
          </div>
        )}

        {/* Notification bell (live mode only) */}
        {!IS_DEMO && notificationCount > 0 && (
          <button
            onClick={() => setNotificationCount(0)}
            className="relative text-text-muted hover:text-text-primary transition-colors"
            title={`${notificationCount} new events`}
          >
            <Bell className="w-4 h-4" />
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-accent-rose text-white text-[9px] font-bold rounded-full flex items-center justify-center">
              {notificationCount > 9 ? "9+" : notificationCount}
            </span>
          </button>
        )}

        {/* Connection status */}
        <div className="flex items-center gap-1.5">
          {IS_DEMO ? (
            <>
              <FlaskConical className="w-3.5 h-3.5 text-accent-amber" />
              <span className="text-xs font-mono text-accent-amber">DEMO</span>
            </>
          ) : connected ? (
            <>
              <Wifi className="w-3.5 h-3.5 text-accent-emerald" />
              <span className="text-xs font-mono text-accent-emerald">LIVE</span>
            </>
          ) : (
            <>
              <WifiOff className="w-3.5 h-3.5 text-accent-rose" />
              <span className="text-xs font-mono text-accent-rose">
                {reconnectCount > 0 ? `RETRY #${reconnectCount}` : "OFFLINE"}
              </span>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
