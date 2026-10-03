import type { Metadata } from "next";
import Link from "next/link";
import { getDashboardMetrics } from "@/server/findings/service";

export const metadata: Metadata = { title: "Overview" };

export default async function DashboardPage() {
  const metrics = await getDashboardMetrics();
  const cards = [
    { label: "Monitored assets", value: metrics.assetCount, hint: `${metrics.verifiedCount} ownership verified` },
    { label: "Open findings", value: metrics.openCount, hint: `${metrics.overdueCount} past remediation SLA` },
    { label: "Risk score", value: metrics.riskScore, hint: "Average of the five highest active risks" },
    { label: "Active scans", value: metrics.runningScans, hint: "Queued or currently running" },
  ];
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const total = Math.max(1, severityOrder.reduce((sum, item) => sum + Number(metrics.severity[item] ?? 0), 0));
  return <div className="mx-auto max-w-6xl">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm font-medium text-[var(--accent)]">CONTROL PLANE</p><h1 className="mt-2 text-3xl font-semibold tracking-tight">Attack surface overview</h1><p className="mt-2 text-[var(--muted)]">Live exposure, remediation pressure, and scanning activity.</p></div><span className="rounded-full border border-emerald-300/20 bg-emerald-300/5 px-3 py-1.5 text-xs font-medium text-[var(--accent)]">● System ready</span></div>
    <section className="mt-10 grid gap-4 md:grid-cols-2 xl:grid-cols-4">{cards.map((card) => <article key={card.label} className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5"><p className="text-sm text-[var(--muted)]">{card.label}</p><p className="mt-4 text-4xl font-semibold">{card.value}</p><p className="mt-5 text-xs leading-5 text-[var(--muted)]">{card.hint}</p></article>)}</section>
    <div className="mt-6 grid gap-6 lg:grid-cols-2"><section className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6"><h2 className="font-semibold">Active severity distribution</h2><div className="mt-6 space-y-4">{severityOrder.map((severity) => { const count = Number(metrics.severity[severity] ?? 0); return <div key={severity}><div className="mb-2 flex justify-between text-sm"><span className="capitalize text-[var(--muted)]">{severity}</span><span>{count}</span></div><div className="h-2 overflow-hidden rounded bg-white/5"><div className="h-full rounded bg-[var(--accent)]" style={{ width: `${(count / total) * 100}%` }}/></div></div>; })}</div></section>
      <section className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6"><div className="flex justify-between"><h2 className="font-semibold">Highest active risks</h2><Link href="/findings" className="text-sm text-[var(--accent)]">View all</Link></div><div className="mt-5 space-y-3">{metrics.topFindings.length === 0 && <p className="py-8 text-center text-sm text-[var(--muted)]">Complete a passive scan to generate findings.</p>}{metrics.topFindings.map((finding) => <Link key={finding._id.toHexString()} href={`/findings/${finding._id.toHexString()}`} className="flex items-center justify-between gap-4 rounded-lg bg-[var(--surface-raised)] p-3"><div className="min-w-0"><p className="truncate text-sm font-medium">{finding.title}</p><p className="mt-1 text-xs uppercase text-[var(--muted)]">{finding.severity}</p></div><span className="text-xl font-semibold">{finding.riskScore}</span></Link>)}</div></section>
    </div>
    <section className="mt-6 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6"><h2 className="font-semibold">Risk trend</h2><p className="mt-1 text-xs text-[var(--muted)]">Latest completed scan snapshots</p><div className="mt-6 flex h-36 items-end gap-2">{metrics.trend.length === 0 && <p className="m-auto text-sm text-[var(--muted)]">No trend data yet.</p>}{metrics.trend.map((point) => <div key={point._id.toHexString()} className="group flex min-w-4 flex-1 flex-col items-center justify-end"><span className="mb-2 text-xs opacity-0 transition group-hover:opacity-100">{point.riskScore}</span><div className="w-full rounded-t bg-[var(--accent)]/70" style={{ height: `${Math.max(4, point.riskScore)}%` }}/></div>)}</div></section>
  </div>;
}
