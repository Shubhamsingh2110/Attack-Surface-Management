import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getScanRunDetails } from "@/server/scans/service";

export const metadata: Metadata = { title: "Scan evidence" };

export default async function ScanDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const run = await getScanRunDetails((await params).id);
  if (!run) notFound();
  return <div className="mx-auto max-w-5xl">
    <Link href="/scans" className="text-sm text-[var(--muted)] hover:text-white">← Scan history</Link>
    <div className="mt-6 flex flex-wrap items-end justify-between gap-4"><div><p className="font-mono text-[var(--accent)]">{run.assetValue}</p><h1 className="mt-2 text-3xl font-semibold">Passive scan evidence</h1></div><span className="rounded-full border border-[var(--border)] px-3 py-1.5 text-sm">{run.status}</span></div>
    <div className="mt-8 space-y-4">{run.observations.length === 0 && <p className="rounded-xl border border-dashed border-[var(--border)] p-10 text-center text-[var(--muted)]">Evidence will appear as workflow steps complete.</p>}{run.observations.map((observation) => <section key={observation._id} className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5"><div className="flex justify-between"><h2 className="font-semibold uppercase tracking-wide">{observation.type}</h2><time className="text-xs text-[var(--muted)]">{observation.observedAt.toLocaleString()}</time></div><pre className="mt-4 max-h-96 overflow-auto rounded-lg bg-[#080d15] p-4 text-xs leading-5 text-slate-300">{JSON.stringify(observation.data, null, 2)}</pre></section>)}</div>
  </div>;
}
