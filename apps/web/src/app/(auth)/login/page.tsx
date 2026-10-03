import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getCurrentAdmin } from "@/server/auth/session";
import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Admin sign in" };

export default async function LoginPage() {
  if (await getCurrentAdmin()) redirect("/dashboard");
  return (
    <main className="grid min-h-screen place-items-center px-6 py-12">
      <section className="w-full max-w-md rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-8 shadow-2xl shadow-black/30">
        <div className="mb-8 flex items-center gap-3">
          <span className="grid size-11 place-items-center rounded-xl border border-emerald-300/20 bg-emerald-300/10 font-mono text-sm font-bold text-[var(--accent)]">ASM</span>
          <div><p className="font-semibold">ASM Control</p><p className="text-sm text-[var(--muted)]">Secure administration</p></div>
        </div>
        <h1 className="text-2xl font-semibold tracking-tight">Welcome back</h1>
        <p className="mt-2 text-sm leading-6 text-[var(--muted)]">Sign in to manage your external attack surface.</p>
        <LoginForm />
      </section>
    </main>
  );
}
