import type { Metadata } from "next";
import Link from "next/link";
import { listFindings } from "@/server/findings/service";
import { bulkFindingAction } from "./actions";

export const metadata: Metadata = { title: "Findings" };

const severityColor: Record<string, string> = { critical: "text-fuchsia-300", high: "text-red-300", medium: "text-amber-300", low: "text-blue-300", info: "text-slate-300" };

export default async function FindingsPage({ searchParams }: { searchParams: Promise<{ status?: string; severity?: string; q?: string; message?: string; error?: string }> }) {
  const params = await searchParams;
  const findings = await listFindings({ status: params.status, severity: params.severity, query: params.q });
  return <div className="mx-auto max-w-7xl">
    <p className="text-sm font-medium text-[var(--accent)]">EXPOSURE</p><h1 className="mt-2 text-3xl font-semibold">Security findings</h1><p className="mt-2 text-[var(--muted)]">Prioritized, explainable issues generated from completed passive scans.</p>
    {(params.message || params.error) && <p className={`mt-6 rounded-lg border px-4 py-3 text-sm ${params.error ? "border-red-400/20 text-[var(--danger)]" : "border-emerald-300/20 text-[var(--accent)]"}`}>{params.error ?? params.message}</p>}
    <form className="mt-7 grid gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4 md:grid-cols-[1fr_180px_180px_auto]">
      <input name="q" defaultValue={params.q} placeholder="Search findings" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"/>
      <select name="status" defaultValue={params.status ?? ""} className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="accepted">Accepted</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select>
      <select name="severity" defaultValue={params.severity ?? ""} className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select>
      <button className="rounded-lg border border-[var(--border)] px-4 py-2">Filter</button>
    </form>
    <form action={bulkFindingAction} className="mt-5 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
      <div className="flex flex-wrap justify-between gap-3 border-b border-[var(--border)] p-3"><span className="text-sm text-[var(--muted)]">{findings.length} findings</span><div className="flex gap-2"><select name="status" className="rounded border border-[var(--border)] bg-[#080d15] px-2 py-1.5 text-sm"><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option><option value="accepted">Accept 30 days</option><option value="open">Reopen</option></select><button className="rounded bg-white/10 px-3 py-1.5 text-sm">Apply selected</button></div></div>
      {findings.length === 0 && <p className="p-12 text-center text-[var(--muted)]">No findings match the current filters.</p>}
      {findings.map((finding) => <div key={finding._id} className="grid grid-cols-[28px_90px_1fr_100px_80px] items-center gap-3 border-b border-[var(--border)] px-4 py-4 text-sm last:border-0"><input type="checkbox" name="findingIds" value={finding._id} aria-label={`Select ${finding.title}`}/><span className={`font-semibold uppercase ${severityColor[finding.severity]}`}>{finding.severity}</span><Link href={`/findings/${finding._id}`} className="min-w-0"><span className="block truncate font-medium hover:text-[var(--accent)]">{finding.title}</span><span className="mt-1 block truncate text-xs text-[var(--muted)]">{finding.assetValue} · Last seen {finding.lastSeenAt.toLocaleDateString()}</span></Link><span className="text-[var(--muted)]">{finding.status.replace("_", " ")}</span><span className="text-right text-lg font-semibold">{finding.riskScore}</span></div>)}
    </form>
  </div>;
}
