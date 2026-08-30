import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "../styles/globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "GuardMind — Autonomous SecOps AI",
  description:
    "GuardMind is an autonomous AI-powered security operations agent. Real-time CVE triage, sandboxed patch verification, and human-in-the-loop GitHub PR creation — all in one pipeline.",
  keywords: [
    "GuardMind",
    "SecOps AI",
    "CVE remediation",
    "vulnerability patching",
    "DevSecOps automation",
    "AI security agent",
  ],
  openGraph: {
    title: "GuardMind — Autonomous SecOps AI",
    description:
      "AI agent that automatically triages, patches, and verifies security vulnerabilities with human-in-the-loop approval.",
    type: "website",
  },
  robots: "index, follow",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className={`${inter.variable} antialiased`}>
        {children}
      </body>
    </html>
  );
}
