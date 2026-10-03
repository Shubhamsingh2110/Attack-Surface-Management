"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navigation = [
  { label: "Overview", href: "/dashboard" },
  { label: "Assets", href: "/assets" },
  { label: "Findings", href: "/findings" },
  { label: "Scans", href: "/scans" },
  { label: "Reports", href: "/reports" },
  { label: "Integrations", href: "/integrations" },
];

export function SidebarNavigation() {
  const pathname = usePathname();

  return (
    <nav className="mt-8 hidden space-y-1 lg:block" aria-label="Primary navigation">
      {navigation.map((item) => {
        const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
        return (
          <Link
            href={item.href}
            key={item.href}
            aria-current={active ? "page" : undefined}
            className={`relative block rounded-lg border px-3 py-2.5 text-sm transition ${
              active
                ? "border-emerald-300/20 bg-emerald-300/10 font-medium text-[var(--accent)] shadow-sm shadow-emerald-950/30 before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:rounded-full before:bg-[var(--accent)]"
                : "border-transparent text-[var(--muted)] hover:bg-white/5 hover:text-white"
            }`}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
