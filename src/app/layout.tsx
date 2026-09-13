import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "The Agent That Earns Trust",
  description: "A trust layer for AI agents: identity, verifiable credentials, and policy-gated authority.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
