/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // SecOps-AI Cyberpunk Palette
        bg: {
          primary: "#0F172A",
          secondary: "#1E293B",
          tertiary: "#0D1B2A",
          card: "#162032",
          hover: "#1A2A42",
        },
        accent: {
          emerald: "#10B981",
          "emerald-dim": "#065F46",
          cyan: "#06B6D4",
          "cyan-dim": "#164E63",
          rose: "#F43F5E",
          "rose-dim": "#881337",
          amber: "#F59E0B",
          "amber-dim": "#78350F",
          purple: "#A855F7",
          "purple-dim": "#581C87",
        },
        text: {
          primary: "#F1F5F9",
          secondary: "#CBD5E1",
          muted: "#64748B",
          code: "#7DD3FC",
        },
        border: {
          subtle: "#1E293B",
          dim: "#334155",
          glow: "rgba(6, 182, 212, 0.3)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "Consolas", "monospace"],
      },
      boxShadow: {
        glow: "0 0 12px rgba(16, 185, 129, 0.4)",
        "glow-cyan": "0 0 12px rgba(6, 182, 212, 0.4)",
        "glow-rose": "0 0 12px rgba(244, 63, 94, 0.4)",
        "glow-amber": "0 0 12px rgba(245, 158, 11, 0.4)",
        "card-hover": "0 4px 24px rgba(6, 182, 212, 0.15)",
      },
      animation: {
        "pulse-glow": "pulseGlow 2s ease-in-out infinite",
        "slide-in": "slideIn 0.3s ease-out",
        "fade-in": "fadeIn 0.4s ease-out",
        "scan-line": "scanLine 3s linear infinite",
      },
      keyframes: {
        pulseGlow: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.6" },
        },
        slideIn: {
          from: { transform: "translateY(-8px)", opacity: "0" },
          to: { transform: "translateY(0)", opacity: "1" },
        },
        fadeIn: {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        scanLine: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
      },
    },
  },
  plugins: [],
};
