import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: "cyan" | "emerald" | "rose" | "amber" | "purple";
  trend?: { value: number; label: string };
  className?: string;
}

const VARIANT_STYLES = {
  cyan: {
    icon: "text-accent-cyan",
    iconBg: "bg-accent-cyan/10 border-accent-cyan/20",
    value: "text-accent-cyan",
    glow: "hover:shadow-glow-cyan",
    border: "hover:border-accent-cyan/30",
  },
  emerald: {
    icon: "text-accent-emerald",
    iconBg: "bg-accent-emerald/10 border-accent-emerald/20",
    value: "text-accent-emerald",
    glow: "hover:shadow-glow",
    border: "hover:border-accent-emerald/30",
  },
  rose: {
    icon: "text-accent-rose",
    iconBg: "bg-accent-rose/10 border-accent-rose/20",
    value: "text-accent-rose",
    glow: "hover:shadow-glow-rose",
    border: "hover:border-accent-rose/30",
  },
  amber: {
    icon: "text-accent-amber",
    iconBg: "bg-accent-amber/10 border-accent-amber/20",
    value: "text-accent-amber",
    glow: "hover:shadow-glow-amber",
    border: "hover:border-accent-amber/30",
  },
  purple: {
    icon: "text-accent-purple",
    iconBg: "bg-accent-purple/10 border-accent-purple/20",
    value: "text-accent-purple",
    glow: "",
    border: "hover:border-accent-purple/30",
  },
};

export function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = "cyan",
  trend,
  className,
}: MetricCardProps) {
  const styles = VARIANT_STYLES[variant];

  return (
    <div
      className={clsx(
        "card transition-all duration-300 cursor-default",
        styles.glow,
        styles.border,
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2">
            {title}
          </p>
          <p className={clsx("text-3xl font-bold font-mono", styles.value)}>
            {value}
          </p>
          {subtitle && (
            <p className="text-xs text-text-muted mt-1">{subtitle}</p>
          )}
          {trend && (
            <div className="flex items-center gap-1 mt-2">
              <span
                className={clsx(
                  "text-xs font-mono",
                  trend.value >= 0 ? "text-accent-emerald" : "text-accent-rose"
                )}
              >
                {trend.value >= 0 ? "↑" : "↓"} {Math.abs(trend.value)}%
              </span>
              <span className="text-xs text-text-muted">{trend.label}</span>
            </div>
          )}
        </div>
        <div
          className={clsx(
            "w-10 h-10 rounded-lg border flex items-center justify-center flex-shrink-0",
            styles.iconBg
          )}
        >
          <Icon className={clsx("w-5 h-5", styles.icon)} />
        </div>
      </div>
    </div>
  );
}
