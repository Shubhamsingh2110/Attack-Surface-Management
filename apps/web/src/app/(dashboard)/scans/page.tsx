import type { Metadata } from "next";
import Link from "next/link";
import { listScanRuns } from "@/server/scans/service";

export const metadata: Metadata = { title: "Scans" };

export default async function ScansPage({ searchParams }: { searchParams: Promise<{ message?: string }> }) {
  const [runs, params] = await Promise.all([listScanRuns(), searchParams]);
  return <div className="mx-auto max-w-6xl">
    <p className="text-sm font-medium text-[var(--accent)]">DISCOVERY</p><h1 className="mt-2 text-3xl font-semibold">Passive scan history</h1><p className="mt-2 text-[var(--muted)]">DNS, certificate, and HTTP posture checks for verified targets.</p>
    {params.message && <p className="mt-6 rounded-lg border border-emerald-300/20 bg-emerald-300/5 px-4 py-3 text-sm text-[var(--accent)]">{params.message}</p>}
    <div className="mt-8 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
      <div className="grid grid-cols-[1fr_110px_100px_170px] gap-3 border-b border-[var(--border)] px-5 py-3 text-xs uppercase tracking-wide text-[var(--muted)]"><span>Asset</span><span>Status</span><span>Evidence</span><span>Created</span></div>
      {runs.length === 0 && <p className="p-10 text-center text-[var(--muted)]">No scans have been queued.</p>}
      {runs.map((run) => <Link href={`/scans/${run._id}`} key={run._id} className="grid grid-cols-[1fr_110px_100px_170px] gap-3 border-b border-[var(--border)] px-5 py-4 text-sm transition last:border-0 hover:bg-white/[0.02]"><span className="font-mono">{run.assetValue}</span><span className={run.status === "completed" ? "text-[var(--accent)]" : run.status === "failed" ? "text-[var(--danger)]" : "text-amber-300"}>{run.status}</span><span>{run.observationCount}</span><span className="text-[var(--muted)]">{run.createdAt.toLocaleString()}</span>{run.error && <p className="col-span-4 text-xs text-[var(--danger)]">{run.error}</p>}</Link>)}
    </div>
  </div>;
}
