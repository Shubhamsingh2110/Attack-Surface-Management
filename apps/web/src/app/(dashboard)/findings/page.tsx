import type { Metadata } from "next";
import Link from "next/link";
import { listFindingAssets, listFindings } from "@/server/findings/service";
import { bulkFindingAction } from "./actions";

export const metadata: Metadata = { title: "Findings" };

const severityColor: Record<string, string> = { critical: "text-fuchsia-300", high: "text-red-300", medium: "text-amber-300", low: "text-blue-300", info: "text-slate-300" };

export default async function FindingsPage({ searchParams }: { searchParams: Promise<{ asset?: string; status?: string; severity?: string; q?: string; message?: string; error?: string }> }) {
  const params = await searchParams;
  const [findings, assets] = await Promise.all([
    listFindings({ assetId: params.asset, status: params.status, severity: params.severity, query: params.q }),
    listFindingAssets(),
  ]);
  const groups = [...Map.groupBy(findings, (finding) => finding.assetValue)].sort(([a], [b]) => a.localeCompare(b));
  const counts = findings.reduce<Record<string, number>>((all, finding) => ({ ...all, [finding.severity]: (all[finding.severity] ?? 0) + 1 }), {});
  const hasFilters = Boolean(params.asset || params.status || params.severity || params.q);
  return <div className="mx-auto max-w-7xl">
    <p className="text-sm font-medium text-[var(--accent)]">EXPOSURE</p><h1 className="mt-2 text-3xl font-semibold">Security findings by domain</h1><p className="mt-2 text-[var(--muted)]">See exactly which website each issue belongs to, why it matters, and what to fix first.</p>
    {(params.message || params.error) && <p className={`mt-6 rounded-lg border px-4 py-3 text-sm ${params.error ? "border-red-400/20 text-[var(--danger)]" : "border-emerald-300/20 text-[var(--accent)]"}`}>{params.error ?? params.message}</p>}
    <div className="mt-7 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4"><p className="text-xs uppercase tracking-wide text-[var(--muted)]">Matching issues</p><p className="mt-2 text-3xl font-semibold">{findings.length}</p></div>
      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4"><p className="text-xs uppercase tracking-wide text-[var(--muted)]">Affected domains</p><p className="mt-2 text-3xl font-semibold">{groups.length}</p></div>
      <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4"><p className="text-xs uppercase tracking-wide text-red-300">Critical + high</p><p className="mt-2 text-3xl font-semibold text-red-200">{(counts.critical ?? 0) + (counts.high ?? 0)}</p></div>
      <div className="rounded-xl border border-amber-300/20 bg-amber-300/5 p-4"><p className="text-xs uppercase tracking-wide text-amber-200">Medium</p><p className="mt-2 text-3xl font-semibold text-amber-100">{counts.medium ?? 0}</p></div>
    </div>
    <form className="mt-5 grid gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4 lg:grid-cols-[minmax(220px,1fr)_minmax(180px,260px)_160px_160px_auto]">
      <input name="q" defaultValue={params.q} placeholder="Search issue or domain" aria-label="Search issue or domain" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"/>
      <select name="asset" defaultValue={params.asset ?? ""} aria-label="Filter by domain" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="">All domains</option>{assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.value}</option>)}</select>
      <select name="status" defaultValue={params.status ?? ""} className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="accepted">Accepted</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select>
      <select name="severity" defaultValue={params.severity ?? ""} className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select>
      <div className="flex gap-2"><button className="flex-1 rounded-lg bg-[var(--accent)] px-4 py-2 font-medium text-[#04120d]">Apply</button>{hasFilters && <Link href="/findings" className="rounded-lg border border-[var(--border)] px-4 py-2 text-center text-sm leading-6 text-[var(--muted)] hover:text-white">Clear</Link>}</div>
    </form>
    <form action={bulkFindingAction} className="mt-5">
      <div className="sticky top-3 z-10 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--border)] bg-[#0c1420]/95 p-3 shadow-xl backdrop-blur"><span className="text-sm text-[var(--muted)]">Select issues below to update their workflow status</span><div className="flex gap-2"><select name="status" className="rounded border border-[var(--border)] bg-[#080d15] px-2 py-1.5 text-sm"><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option><option value="accepted">Accept 30 days</option><option value="open">Reopen</option></select><button className="rounded bg-white/10 px-3 py-1.5 text-sm hover:bg-white/15">Apply selected</button></div></div>
      {findings.length === 0 && <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-12 text-center"><p className="font-medium">No matching security issues</p><p className="mt-2 text-sm text-[var(--muted)]">Try clearing one or more filters.</p></div>}
      <div className="mt-4 space-y-5">{groups.map(([domain, domainFindings]) => <section key={domain} className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] bg-white/[0.025] px-5 py-4"><div><p className="text-xs uppercase tracking-wider text-[var(--muted)]">Issues found on</p><h2 className="mt-1 font-mono text-lg font-semibold text-[var(--accent)]">{domain}</h2></div><span className="rounded-full border border-[var(--border)] bg-black/20 px-3 py-1 text-sm text-[var(--muted)]">{domainFindings.length} {domainFindings.length === 1 ? "issue" : "issues"}</span></header>
        <div className="divide-y divide-[var(--border)]">{domainFindings.map((finding) => <div key={finding._id} className="grid gap-3 px-5 py-4 sm:grid-cols-[28px_100px_minmax(0,1fr)_120px_70px] sm:items-center"><input type="checkbox" name="findingIds" value={finding._id} aria-label={`Select ${finding.title}`}/><span className={`text-xs font-semibold uppercase ${severityColor[finding.severity]}`}>{finding.severity}</span><Link href={`/findings/${finding._id}`} className="min-w-0 group"><span className="block font-medium group-hover:text-[var(--accent)]">{finding.title}</span><span className="mt-1 block truncate text-xs text-[var(--muted)]">{finding.description}</span><span className="mt-1 block text-xs text-slate-500">Last detected {finding.lastSeenAt.toLocaleDateString()}</span></Link><span className="text-sm capitalize text-[var(--muted)]">{finding.status.replace("_", " ")}</span><span className="text-left sm:text-right"><span className="text-xs text-[var(--muted)] sm:hidden">Risk </span><span className="text-lg font-semibold">{finding.riskScore}</span></span></div>)}</div>
      </section>)}</div>
    </form>
  </div>;
}
