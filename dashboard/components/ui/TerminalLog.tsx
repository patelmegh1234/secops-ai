"use client";

import { useEffect, useRef, useState } from "react";
import { clsx } from "clsx";
import { Terminal, ChevronDown } from "lucide-react";

interface TerminalLogProps {
  content: string;
  title?: string;
  passed?: boolean;
  className?: string;
  maxHeight?: string;
}

export function TerminalLog({
  content,
  title = "Sandbox Output",
  passed,
  className,
  maxHeight = "300px",
}: TerminalLogProps) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [content, autoScroll]);

  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 30;
    setAutoScroll(isAtBottom);
  };

  const lines = content.split("\n");

  const lineColor = (line: string) => {
    if (line.toLowerCase().includes("passed") || line.includes("✅")) {
      return "text-accent-emerald";
    }
    if (
      line.toLowerCase().includes("failed") ||
      line.toLowerCase().includes("error") ||
      line.includes("❌")
    ) {
      return "text-accent-rose";
    }
    if (line.startsWith(">>>") || line.includes("WARNING")) {
      return "text-accent-amber";
    }
    if (line.startsWith("#") || line.startsWith("==")) {
      return "text-accent-cyan/70";
    }
    return "text-text-secondary";
  };

  return (
    <div className={clsx("rounded-xl overflow-hidden border border-border-subtle", className)}>
      {/* Header */}
      <div className="flex items-center justify-between bg-bg-secondary px-4 py-2 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-text-muted" />
          <span className="text-xs font-mono text-text-muted">{title}</span>
        </div>
        {typeof passed !== "undefined" && (
          <span className={clsx("text-xs font-mono font-semibold",
            passed ? "text-accent-emerald" : "text-accent-rose"
          )}>
            {passed ? "● PASSED" : "● FAILED"}
          </span>
        )}
      </div>

      {/* Content */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="bg-bg-tertiary font-mono text-xs overflow-auto"
        style={{ maxHeight }}
      >
        <div className="p-4 space-y-0.5">
          {lines.map((line, i) => (
            <div key={i} className={clsx("leading-5 whitespace-pre-wrap break-all", lineColor(line))}>
              {line || "\u00A0"}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && (
        <button
          onClick={() => {
            setAutoScroll(true);
            bottomRef.current?.scrollIntoView({ behavior: "smooth" });
          }}
          className="absolute bottom-3 right-3 bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan text-xs font-mono px-2 py-1 rounded-md flex items-center gap-1 transition-colors"
        >
          <ChevronDown className="w-3 h-3" />
          Scroll to end
        </button>
      )}
    </div>
  );
}
