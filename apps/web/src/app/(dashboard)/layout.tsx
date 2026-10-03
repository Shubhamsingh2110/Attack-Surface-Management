import Link from "next/link";
import { redirect } from "next/navigation";
import { logoutAction } from "@/app/(auth)/login/actions";
import { getCurrentAdmin } from "@/server/auth/session";
import { SidebarNavigation } from "./sidebar-navigation";

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
        <SidebarNavigation />
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
