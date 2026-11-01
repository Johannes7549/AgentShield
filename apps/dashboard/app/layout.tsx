import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentShield",
  description: "Security operations console foundation",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-ink font-sans text-slate-100 antialiased">{children}</body>
    </html>
  );
}
