"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  LayoutDashboard,
  ScrollText,
  Plug,
  Settings,
  ChevronRight,
  Zap,
  Github,
} from "lucide-react";
import { clsx } from "clsx";

const navSections = [
  {
    label: "Operations",
    items: [
      {
        href: "/dashboard",
        label: "Command Center",
        icon: LayoutDashboard,
        description: "Live CVE feed & KPIs",
      },
      {
        href: "/audit",
        label: "Audit Log",
        icon: ScrollText,
        description: "History & compliance",
      },
    ],
  },
  {
    label: "Configuration",
    items: [
      {
        href: "/integrations",
        label: "Integrations",
        icon: Plug,
        description: "GitHub, Slack, scanners",
      },
      {
        href: "/settings",
        label: "Settings",
        icon: Settings,
        description: "Workspace & API keys",
      },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-60 bg-bg-tertiary border-r border-border-subtle flex flex-col flex-shrink-0">
      {/* Logo / Brand */}
      <Link
        href="/"
        className="flex items-center gap-3 px-5 py-5 border-b border-border-subtle group"
      >
        <div className="w-8 h-8 bg-gradient-to-br from-accent-cyan/30 to-accent-emerald/20 border border-accent-cyan/40 rounded-lg flex items-center justify-center transition-all group-hover:border-accent-cyan/60 group-hover:shadow-glow-cyan">
          <Shield className="w-4 h-4 text-accent-cyan" />
        </div>
        <div>
          <div className="text-sm font-bold text-text-primary tracking-tight">
            Guard<span className="text-accent-cyan">Mind</span>
          </div>
          <div className="text-[10px] text-text-muted font-mono tracking-widest uppercase">
            SecOps AI
          </div>
        </div>
      </Link>

      {/* Workspace badge */}
      <div className="mx-3 mt-4 px-3 py-2.5 rounded-lg bg-bg-secondary border border-border-subtle">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-text-primary">Acme Corp</div>
            <div className="text-[10px] text-text-muted font-mono mt-0.5">Free Plan</div>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-emerald animate-pulse" />
            <span className="text-[10px] font-mono text-accent-emerald">LIVE</span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-6 overflow-y-auto">
        {navSections.map((section) => (
          <div key={section.label}>
            <div className="text-[10px] font-mono text-text-muted uppercase tracking-widest px-3 mb-2">
              {section.label}
            </div>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive =
                  pathname === item.href ||
                  (item.href !== "/" && pathname.startsWith(item.href));

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={clsx(
                      "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150 group relative",
                      isActive
                        ? "text-accent-cyan bg-accent-cyan/10 border border-accent-cyan/20"
                        : "text-text-muted hover:text-text-primary hover:bg-bg-hover border border-transparent"
                    )}
                  >
                    {isActive && (
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-accent-cyan rounded-r-full" />
                    )}
                    <Icon
                      className={clsx(
                        "w-4 h-4 flex-shrink-0 transition-colors",
                        isActive
                          ? "text-accent-cyan"
                          : "text-text-muted group-hover:text-text-secondary"
                      )}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium leading-tight">{item.label}</div>
                      <div
                        className={clsx(
                          "text-[10px] font-mono leading-tight truncate mt-0.5",
                          isActive ? "text-accent-cyan/60" : "text-text-muted"
                        )}
                      >
                        {item.description}
                      </div>
                    </div>
                    {isActive && (
                      <ChevronRight className="w-3 h-3 text-accent-cyan/50 flex-shrink-0" />
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-border-subtle space-y-3">
        {/* User row */}
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-accent-cyan/40 to-accent-emerald/30 border border-accent-cyan/30 flex items-center justify-center flex-shrink-0">
            <span className="text-[10px] font-bold text-accent-cyan">MP</span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-medium text-text-secondary truncate">Megh Patel</div>
            <div className="text-[10px] text-text-muted font-mono truncate">Admin</div>
          </div>
        </div>
        {/* Version */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Zap className="w-3 h-3 text-accent-amber" />
            <span className="text-[10px] font-mono text-text-muted">v1.0.0 · GPT-4o</span>
          </div>
          <a
            href="https://github.com/patelmegh1234/secops-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-muted hover:text-text-secondary transition-colors"
            title="GitHub"
          >
            <Github className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>
    </aside>
  );
}
