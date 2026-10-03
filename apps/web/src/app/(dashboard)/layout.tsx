import Link from "next/link";
import { redirect } from "next/navigation";
import { logoutAction } from "@/app/(auth)/login/actions";
import { getCurrentAdmin } from "@/server/auth/session";

const navigation = [
  { label: "Overview", href: "/dashboard" },
  { label: "Assets", href: "/assets" },
  { label: "Findings", href: "/findings" },
  { label: "Scans", href: "/scans" },
  { label: "Reports", href: "/reports" },
];

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const admin = await getCurrentAdmin();
  if (!admin) redirect("/login");

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[260px_1fr]">
      <aside className="border-b border-[var(--border)] bg-[var(--surface)] p-5 lg:min-h-screen lg:border-b-0 lg:border-r">
        <Link href="/dashboard" className="flex items-center gap-3">
          <span className="grid size-10 place-items-center rounded-xl bg-emerald-300/10 font-mono text-sm font-bold text-[var(--accent)]">ASM</span>
          <span className="font-semibold">ASM Control</span>
        </Link>
        <nav className="mt-8 hidden space-y-1 lg:block" aria-label="Primary navigation">
          {navigation.map((item, index) => (
            <Link href={item.href} key={item.href} className={`block rounded-lg px-3 py-2.5 text-sm transition hover:bg-white/5 hover:text-white ${index === 0 ? "text-[var(--accent)]" : "text-[var(--muted)]"}`}>{item.label}</Link>
          ))}
        </nav>
        <div className="mt-8 hidden border-t border-[var(--border)] pt-5 lg:block">
          <p className="truncate text-sm font-medium">{admin.name}</p>
          <p className="mt-1 truncate text-xs text-[var(--muted)]">{admin.email}</p>
          <form action={logoutAction}><button className="mt-4 text-sm text-[var(--muted)] transition hover:text-white">Sign out</button></form>
        </div>
      </aside>
      <main className="p-6 md:p-10">{children}</main>
    </div>
  );
}
