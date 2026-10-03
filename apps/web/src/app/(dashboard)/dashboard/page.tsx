import type { Metadata } from "next";

export const metadata: Metadata = { title: "Overview" };

const cards = [
  { label: "Monitored assets", value: "0", hint: "Asset discovery begins in Phase 2" },
  { label: "Open findings", value: "0", hint: "No current exposure detected" },
  { label: "Risk score", value: "—", hint: "Waiting for the first verified asset" },
];

export default function DashboardPage() {
  return (
    <div className="mx-auto max-w-6xl">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div><p className="text-sm font-medium text-[var(--accent)]">CONTROL PLANE</p><h1 className="mt-2 text-3xl font-semibold tracking-tight">Attack surface overview</h1><p className="mt-2 text-[var(--muted)]">Your secure foundation is online.</p></div>
        <span className="rounded-full border border-emerald-300/20 bg-emerald-300/5 px-3 py-1.5 text-xs font-medium text-[var(--accent)]">● System ready</span>
      </div>
      <section className="mt-10 grid gap-4 md:grid-cols-3">
        {cards.map((card) => <article key={card.label} className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5"><p className="text-sm text-[var(--muted)]">{card.label}</p><p className="mt-4 text-4xl font-semibold">{card.value}</p><p className="mt-5 text-xs leading-5 text-[var(--muted)]">{card.hint}</p></article>)}
      </section>
      <section className="mt-6 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6">
        <h2 className="font-semibold">Phase 1 complete</h2>
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          {["Single-admin authentication", "Database-backed sessions", "Login lockout protection", "Immutable audit events", "Vercel-ready configuration", "Security response headers"].map((item) => <div key={item} className="flex items-center gap-3 rounded-lg bg-[var(--surface-raised)] px-4 py-3 text-sm"><span className="text-[var(--accent)]">✓</span>{item}</div>)}
        </div>
      </section>
    </div>
  );
}
