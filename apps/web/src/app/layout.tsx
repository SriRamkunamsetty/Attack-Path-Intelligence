import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "AttackPath Intelligence | Reasoning Engine & ATT&CK Validator",
  description: "Evidence-driven attack chain reconstruction, reasoning, and MITRE ATT&CK validation.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased bg-slate-950 text-slate-100 min-h-screen">
        {children}
      </body>
    </html>
  );
}
