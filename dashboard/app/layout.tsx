import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "../styles/globals.css";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: {
    default: "GuardMind — Autonomous SecOps AI",
    template: "%s | GuardMind",
  },
  description:
    "GuardMind is an autonomous AI-powered security operations agent. Real-time CVE triage, sandboxed patch verification, and human-in-the-loop GitHub PR creation — all in one pipeline.",
  keywords: [
    "GuardMind",
    "SecOps AI",
    "CVE remediation",
    "vulnerability patching",
    "DevSecOps automation",
    "AI security agent",
    "Trivy",
    "Bandit",
  ],
  openGraph: {
    title: "GuardMind — Autonomous SecOps AI",
    description:
      "AI agent that automatically triages, patches, and verifies security vulnerabilities with human-in-the-loop approval.",
    type: "website",
  },
  robots: "noindex, nofollow",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link
          rel="preconnect"
          href="https://fonts.googleapis.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className={`${inter.variable} bg-bg-primary text-text-primary antialiased`}>
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <div className="flex flex-col flex-1 overflow-hidden">
            <TopBar />
            <main className="flex-1 overflow-auto p-6 grid-pattern">
              {children}
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
