import type { Metadata } from "next";
import { listReports } from "@/server/reports/service";
import { createReportAction } from "./actions";

export const metadata: Metadata = { title: "Reports" };

export default async function ReportsPage({ searchParams }: { searchParams: Promise<{ message?: string; error?: string }> }) {
  const [params, reports] = await Promise.all([searchParams, listReports()]);
  return <div className="mx-auto max-w-6xl">
    <p className="text-sm font-medium text-[var(--accent)]">EXPORTS</p><h1 className="mt-2 text-3xl font-semibold">Security reports</h1>
    <p className="mt-2 text-[var(--muted)]">Download clear, private reports that connect every security issue to the affected domain and explain how to fix it.</p>
    {(params.message || params.error) && <p className={`mt-6 rounded-lg border px-4 py-3 text-sm ${params.error ? "border-red-400/20 text-[var(--danger)]" : "border-emerald-300/20 text-[var(--accent)]"}`}>{params.error ?? params.message}</p>}
    <div className="mt-7 grid gap-3 md:grid-cols-3"><div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4"><p className="font-medium">Executive summary</p><p className="mt-2 text-sm leading-6 text-[var(--muted)]">Risk totals and issue counts for every affected domain.</p></div><div className="rounded-xl border border-emerald-300/20 bg-emerald-300/5 p-4"><p className="font-medium text-[var(--accent)]">Technical findings</p><p className="mt-2 text-sm leading-6 text-[var(--muted)]">Every bug with domain, evidence, severity, dates, and remediation.</p></div><div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4"><p className="font-medium">Asset inventory</p><p className="mt-2 text-sm leading-6 text-[var(--muted)]">All tracked domains, their priority, and latest scan date.</p></div></div>
    <form action={createReportAction} className="mt-4 grid gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 md:grid-cols-[1fr_180px_auto]">
      <label className="text-sm">What should the report contain?<select name="kind" defaultValue="technical" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="technical">All bugs and remediation</option><option value="executive">Domain risk summary</option><option value="asset_inventory">Asset inventory</option></select></label>
      <label className="text-sm">Format<select name="format" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="pdf">PDF</option><option value="csv">CSV</option></select></label>
      <button className="self-end rounded-lg bg-[var(--accent)] px-4 py-2 font-medium text-[#04120d]">Generate report</button>
    </form>
    <p className="mt-3 text-xs text-[var(--muted)]">PDF is best for sharing. CSV is best for sorting and analysis. Download links are signed and expire after five minutes.</p>
    <div className="mt-6 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
      {reports.length === 0 && <p className="p-10 text-center text-[var(--muted)]">No reports generated yet.</p>}
      {reports.map((report) => <div key={report._id.toHexString()} className="grid gap-2 border-b border-[var(--border)] px-5 py-4 last:border-0 md:grid-cols-[1fr_120px_170px_100px] md:items-center">
        <div><p className="font-medium capitalize">{report.kind.replaceAll("_", " ")}</p><p className="mt-1 text-xs text-[var(--muted)]">Created {report.createdAt.toLocaleString()} · available until {report.expiresAt.toLocaleDateString()}</p></div>
        <span className="text-sm uppercase text-[var(--muted)]">{report.format}{report.bytes ? ` · ${(report.bytes / 1024).toFixed(1)} KB` : ""}</span><span className={report.status === "failed" ? "text-sm capitalize text-[var(--danger)]" : "text-sm capitalize text-[var(--muted)]"}>{report.status}</span>
        {report.status === "ready" ? <a href={`/api/reports/${report._id.toHexString()}/download`} className="rounded border border-[var(--border)] px-3 py-2 text-center text-sm hover:border-emerald-300/30 hover:text-[var(--accent)]">Download {report.format.toUpperCase()}</a> : <span className="text-xs text-[var(--muted)]">{report.error?.slice(0, 80)}</span>}
      </div>)}
    </div>
  </div>;
}
