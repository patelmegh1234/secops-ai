"use client";

import { useState } from "react";
import { clsx } from "clsx";

interface DiffViewerProps {
  diff: string;
  originalCode?: string;
  patchedCode?: string;
  filename?: string;
  className?: string;
}

type ViewMode = "split" | "unified";

export function DiffViewer({
  diff,
  originalCode,
  patchedCode,
  filename = "file.py",
  className,
}: DiffViewerProps) {
  const [viewMode, setViewMode] = useState<ViewMode>("unified");

  if (!diff && !originalCode && !patchedCode) {
    return (
      <div className="code-block text-text-muted text-center py-8">
        No diff available.
      </div>
    );
  }

  return (
    <div className={clsx("rounded-xl overflow-hidden border border-border-subtle", className)}>
      {/* Toolbar */}
      <div className="flex items-center justify-between bg-bg-secondary px-4 py-2 border-b border-border-subtle">
        <span className="text-xs font-mono text-text-muted">{filename}</span>
        <div className="flex items-center gap-1 bg-bg-tertiary rounded-md p-0.5">
          {(["unified", "split"] as ViewMode[]).map((mode) => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              className={clsx(
                "px-2.5 py-1 text-xs font-mono rounded transition-colors capitalize",
                viewMode === mode
                  ? "bg-accent-cyan/20 text-accent-cyan"
                  : "text-text-muted hover:text-text-primary"
              )}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Diff content */}
      {viewMode === "unified" ? (
        <UnifiedDiff diff={diff} />
      ) : (
        <SplitDiff original={originalCode || ""} patched={patchedCode || ""} />
      )}
    </div>
  );
}

function UnifiedDiff({ diff }: { diff: string }) {
  const lines = diff.split("\n");

  return (
    <div className="code-block rounded-none overflow-auto max-h-[500px] text-xs leading-6">
      {lines.map((line, i) => {
        let lineClass = "diff-neutral";
        let prefix = " ";

        if (line.startsWith("+") && !line.startsWith("+++")) {
          lineClass = "diff-added";
          prefix = "+";
        } else if (line.startsWith("-") && !line.startsWith("---")) {
          lineClass = "diff-removed";
          prefix = "-";
        } else if (line.startsWith("@@")) {
          lineClass = "text-accent-cyan/70 italic";
        } else if (line.startsWith("+++") || line.startsWith("---")) {
          lineClass = "text-text-muted";
        }

        return (
          <div key={i} className={clsx("px-4 py-0 flex", lineClass)}>
            <span className="w-6 text-text-muted select-none mr-2 font-mono">
              {i + 1}
            </span>
            <span className="w-4 select-none font-mono">{prefix}</span>
            <span className="font-mono whitespace-pre">{line.slice(1) || line}</span>
          </div>
        );
      })}
    </div>
  );
}

function SplitDiff({ original, patched }: { original: string; patched: string }) {
  const origLines = original.split("\n");
  const patchLines = patched.split("\n");
  const maxLines = Math.max(origLines.length, patchLines.length);

  return (
    <div className="grid grid-cols-2 divide-x divide-border-subtle overflow-auto max-h-[500px]">
      {/* Original */}
      <div className="code-block rounded-none text-xs leading-6">
        <div className="px-3 py-1 text-xs font-mono text-accent-rose border-b border-border-subtle mb-1">
          — original
        </div>
        {origLines.map((line, i) => (
          <div key={i} className="flex px-3 hover:bg-bg-hover">
            <span className="w-8 text-text-muted select-none mr-2 font-mono text-right">
              {i + 1}
            </span>
            <span className="font-mono whitespace-pre text-text-secondary">{line}</span>
          </div>
        ))}
      </div>

      {/* Patched */}
      <div className="code-block rounded-none text-xs leading-6">
        <div className="px-3 py-1 text-xs font-mono text-accent-emerald border-b border-border-subtle mb-1">
          + patched
        </div>
        {patchLines.map((line, i) => (
          <div key={i} className={clsx("flex px-3 hover:bg-bg-hover",
            i < origLines.length && line !== origLines[i] ? "diff-added" : ""
          )}>
            <span className="w-8 text-text-muted select-none mr-2 font-mono text-right">
              {i + 1}
            </span>
            <span className="font-mono whitespace-pre text-text-secondary">{line}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
