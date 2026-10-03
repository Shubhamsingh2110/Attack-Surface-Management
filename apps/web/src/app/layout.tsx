import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "ASM Control", template: "%s · ASM Control" },
  description: "External attack surface management control plane",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
