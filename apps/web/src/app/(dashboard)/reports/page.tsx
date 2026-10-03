import type { Metadata } from "next";
import { listReports } from "@/server/reports/service";
import { createReportAction } from "./actions";

export const metadata: Metadata = { title: "Reports" };

export default async function ReportsPage({ searchParams }: { searchParams: Promise<{ message?: string; error?: string }> }) {
  const [params, reports] = await Promise.all([searchParams, listReports()]);
  return <div className="mx-auto max-w-6xl">
    <p className="text-sm font-medium text-[var(--accent)]">EXPORTS</p><h1 className="mt-2 text-3xl font-semibold">Security reports</h1>
    <p className="mt-2 text-[var(--muted)]">Generate private PDF or CSV exports. Downloads expire after five minutes and stored files follow the configured retention period.</p>
    {(params.message || params.error) && <p className={`mt-6 rounded-lg border px-4 py-3 text-sm ${params.error ? "border-red-400/20 text-[var(--danger)]" : "border-emerald-300/20 text-[var(--accent)]"}`}>{params.error ?? params.message}</p>}
    <form action={createReportAction} className="mt-7 grid gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 md:grid-cols-[1fr_180px_auto]">
      <label className="text-sm">Report type<select name="kind" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="executive">Executive summary</option><option value="technical">Technical findings</option><option value="asset_inventory">Asset inventory</option></select></label>
      <label className="text-sm">Format<select name="format" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="pdf">PDF</option><option value="csv">CSV</option></select></label>
      <button className="self-end rounded-lg bg-[var(--accent)] px-4 py-2 font-medium text-[#04120d]">Generate</button>
    </form>
    <div className="mt-6 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
      {reports.length === 0 && <p className="p-10 text-center text-[var(--muted)]">No reports generated yet.</p>}
      {reports.map((report) => <div key={report._id.toHexString()} className="grid gap-2 border-b border-[var(--border)] px-5 py-4 last:border-0 md:grid-cols-[1fr_120px_170px_100px] md:items-center">
        <div><p className="font-medium">{report.kind.replaceAll("_", " ")}</p><p className="mt-1 text-xs text-[var(--muted)]">Expires {report.expiresAt.toLocaleDateString()}</p></div>
        <span className="text-sm uppercase text-[var(--muted)]">{report.format}</span><span className={report.status === "failed" ? "text-sm text-[var(--danger)]" : "text-sm text-[var(--muted)]"}>{report.status}</span>
        {report.status === "ready" ? <a href={`/api/reports/${report._id.toHexString()}/download`} className="rounded border border-[var(--border)] px-3 py-2 text-center text-sm hover:text-[var(--accent)]">Download</a> : <span className="text-xs text-[var(--muted)]">{report.error?.slice(0, 80)}</span>}
      </div>)}
    </div>
  </div>;
}
