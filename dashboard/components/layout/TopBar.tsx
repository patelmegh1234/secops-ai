"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { Wifi, WifiOff, Bell, Search, HelpCircle } from "lucide-react";
import { useRealtimeFeed } from "@/lib/websocket";
import { clsx } from "clsx";

const IS_DEMO =
  !process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_DEMO_MODE === "true";

const PAGE_TITLES: Record<string, { title: string; subtitle: string }> = {
  "/dashboard": { title: "Command Center", subtitle: "Real-time vulnerability remediation pipeline" },
  "/audit": { title: "Audit Log", subtitle: "Full remediation history & compliance export" },
  "/integrations": { title: "Integrations", subtitle: "Connected scanners, SCM, and notification channels" },
  "/settings": { title: "Settings", subtitle: "Workspace configuration & API key management" },
};

export function TopBar() {
  const pathname = usePathname();
  const [currentTime, setCurrentTime] = useState<string>("");
  const [notificationCount, setNotificationCount] = useState(0);

  const pageInfo = PAGE_TITLES[pathname] ?? {
    title: "GuardMind",
    subtitle: "Autonomous SecOps Agent",
  };

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
    <header className="h-14 bg-bg-tertiary border-b border-border-subtle flex items-center justify-between px-6 flex-shrink-0">
      {/* Left: page title */}
      <div className="flex items-center gap-3">
        <div>
          <h2 className="text-sm font-semibold text-text-primary leading-tight">
            {pageInfo.title}
          </h2>
          <p className="text-[10px] text-text-muted font-mono leading-tight hidden sm:block">
            {pageInfo.subtitle}
          </p>
        </div>
      </div>

      {/* Right: controls */}
      <div className="flex items-center gap-3">
        {/* Live event ticker */}
        {!IS_DEMO && lastEvent && lastEvent.type === "vulnerability_update" && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-accent-emerald/10 border border-accent-emerald/20 animate-fade-in">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-emerald animate-pulse" />
            <span className="text-[10px] font-mono text-accent-emerald max-w-[160px] truncate">
              {lastEvent.severity}: {lastEvent.title?.slice(0, 28)}
            </span>
          </div>
        )}

        {/* Clock */}
        <div className="font-mono text-xs text-text-muted tabular-nums hidden md:block">
          {currentTime}
          <span className="animate-blink ml-0.5 text-accent-cyan/50">|</span>
        </div>

        {/* Search */}
        <button className="p-1.5 text-text-muted hover:text-text-secondary transition-colors rounded-md hover:bg-bg-hover" title="Search (coming soon)">
          <Search className="w-4 h-4" />
        </button>

        {/* Notifications */}
        <button
          onClick={() => setNotificationCount(0)}
          className="relative p-1.5 text-text-muted hover:text-text-secondary transition-colors rounded-md hover:bg-bg-hover"
          title={notificationCount > 0 ? `${notificationCount} new events` : "No new events"}
        >
          <Bell className="w-4 h-4" />
          {notificationCount > 0 && (
            <span className="absolute top-0 right-0 w-3.5 h-3.5 bg-accent-rose text-white text-[8px] font-bold rounded-full flex items-center justify-center">
              {notificationCount > 9 ? "9+" : notificationCount}
            </span>
          )}
        </button>

        {/* Help */}
        <button className="p-1.5 text-text-muted hover:text-text-secondary transition-colors rounded-md hover:bg-bg-hover" title="Documentation">
          <HelpCircle className="w-4 h-4" />
        </button>

        {/* Connection status */}
        <div
          className={clsx(
            "flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border text-[10px] font-mono",
            IS_DEMO
              ? "bg-bg-secondary border-border-subtle text-text-muted"
              : connected
              ? "bg-accent-emerald/10 border-accent-emerald/20 text-accent-emerald"
              : "bg-accent-rose/10 border-accent-rose/20 text-accent-rose"
          )}
        >
          <span
            className={clsx(
              "w-1.5 h-1.5 rounded-full",
              IS_DEMO
                ? "bg-text-muted"
                : connected
                ? "bg-accent-emerald animate-pulse"
                : "bg-accent-rose"
            )}
          />
          {IS_DEMO ? (
            <span>Preview</span>
          ) : connected ? (
            <span>Live</span>
          ) : (
            <>
              {!connected && (
                <WifiOff className="w-3 h-3" />
              )}
              <span>{reconnectCount > 0 ? `Retry #${reconnectCount}` : "Offline"}</span>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
