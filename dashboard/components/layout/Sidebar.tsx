"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  LayoutDashboard,
  FileCode2,
  ScrollText,
  Zap,
} from "lucide-react";
import { clsx } from "clsx";

const navItems = [
  {
    href: "/dashboard",
    label: "Incident Command",
    icon: LayoutDashboard,
    description: "Live CVE feed & metrics",
  },
  {
    href: "/audit",
    label: "Audit Logs",
    icon: ScrollText,
    description: "Full history & compliance",
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-bg-tertiary border-r border-border-subtle flex flex-col flex-shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-border-subtle">
        <div className="w-8 h-8 bg-accent-cyan/10 border border-accent-cyan/30 rounded-lg flex items-center justify-center">
          <Shield className="w-4 h-4 text-accent-cyan" />
        </div>
        <div>
          <div className="text-sm font-bold text-text-primary font-mono tracking-wide">
            SecOps
            <span className="text-accent-cyan">-AI</span>
          </div>
          <div className="text-xs text-text-muted">Autonomous Agent</div>
        </div>
      </div>

      {/* Agent status indicator */}
      <div className="px-4 py-3 mx-3 mt-4 rounded-lg bg-accent-emerald/5 border border-accent-emerald/20">
        <div className="flex items-center gap-2">
          <span className="status-dot active" />
          <span className="text-xs font-mono text-accent-emerald">
            Agent Online
          </span>
        </div>
        <div className="text-xs text-text-muted mt-1 font-mono">
          CrewAI Pipeline Active
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        <div className="text-xs font-mono text-text-muted uppercase tracking-wider px-3 mb-3">
          Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "nav-link group",
                isActive && "active"
              )}
            >
              <Icon
                className={clsx(
                  "w-4 h-4 flex-shrink-0 transition-colors",
                  isActive ? "text-accent-cyan" : "text-text-muted group-hover:text-text-primary"
                )}
              />
              <div>
                <div className="text-sm font-medium">{item.label}</div>
                <div className="text-xs text-text-muted">{item.description}</div>
              </div>
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-border-subtle">
        <div className="flex items-center gap-2">
          <Zap className="w-3 h-3 text-accent-amber" />
          <span className="text-xs font-mono text-text-muted">
            v0.1.0 — GPT-4o
          </span>
        </div>
      </div>
    </aside>
  );
}
