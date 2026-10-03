import type { Metadata } from "next";
import { listAssets } from "@/server/assets/service";
import { addAssetAction, authorizePassiveScanAction, createChallengeAction, startScanAction, verifyAssetAction } from "./actions";

export const metadata: Metadata = { title: "Assets" };

export default async function AssetsPage({ searchParams }: { searchParams: Promise<{ message?: string; error?: string }> }) {
  const [assets, params] = await Promise.all([listAssets(), searchParams]);
  return <div className="mx-auto max-w-6xl">
    <div><p className="text-sm font-medium text-[var(--accent)]">INVENTORY</p><h1 className="mt-2 text-3xl font-semibold">External assets</h1><p className="mt-2 text-[var(--muted)]">Verify ownership or record authorization before running passive assessments.</p></div>
    {(params.message || params.error) && <p className={`mt-6 rounded-lg border px-4 py-3 text-sm ${params.error ? "border-red-400/20 bg-red-400/5 text-[var(--danger)]" : "border-emerald-300/20 bg-emerald-300/5 text-[var(--accent)]"}`}>{params.error ?? params.message}</p>}
    <form action={addAssetAction} className="mt-8 grid gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 md:grid-cols-7">
      <select name="type" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-3"><option value="domain">Domain</option><option value="subdomain">Subdomain</option><option value="ip">IP address</option><option value="cidr">CIDR</option></select>
      <input name="value" required placeholder="example.com" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-3 md:col-span-2" />
      <input name="displayName" placeholder="Display name" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-3" />
      <select name="criticality" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-3"><option value="medium">Medium</option><option value="low">Low</option><option value="high">High</option><option value="critical">Critical</option></select>
      <select name="scanFrequency" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-3"><option value="manual">Manual scans</option><option value="daily">Daily scans</option><option value="weekly">Weekly scans</option></select>
      <button className="rounded-lg bg-[var(--accent)] px-4 py-3 font-semibold text-[#04110c]">Add asset</button>
      <input name="tags" placeholder="Tags, comma separated" className="rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-3 md:col-span-7" />
    </form>
    <section className="mt-6 space-y-4">
      {assets.length === 0 && <div className="rounded-xl border border-dashed border-[var(--border)] p-10 text-center text-[var(--muted)]">No assets yet. Add your first authorized target above.</div>}
      {assets.map((asset) => <article key={asset._id} className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5">
        <div className="flex flex-wrap items-start justify-between gap-4"><div><div className="flex items-center gap-3"><h2 className="font-mono text-lg">{asset.value}</h2><span className={`rounded-full px-2.5 py-1 text-xs ${asset.ownershipStatus === "verified" ? "bg-emerald-300/10 text-[var(--accent)]" : "bg-amber-300/10 text-amber-300"}`}>{asset.verificationMethod === "authorization_attestation" ? "authorized" : asset.ownershipStatus}</span></div><p className="mt-2 text-sm text-[var(--muted)]">{asset.type} · {asset.criticality} criticality · {asset.scanFrequency} scanning {asset.tags.length ? `· ${asset.tags.join(", ")}` : ""}</p></div>
          <div className="flex gap-2">{asset.ownershipStatus === "verified" ? <form action={startScanAction}><input type="hidden" name="assetId" value={asset._id}/><button className="rounded-lg bg-[var(--accent)] px-3 py-2 text-sm font-semibold text-[#04110c]">Start passive scan</button></form> : <><form action={createChallengeAction}><input type="hidden" name="assetId" value={asset._id}/><input type="hidden" name="method" value="dns_txt"/><button className="rounded-lg border border-[var(--border)] px-3 py-2 text-sm">DNS challenge</button></form><form action={createChallengeAction}><input type="hidden" name="assetId" value={asset._id}/><input type="hidden" name="method" value="http_file"/><button className="rounded-lg border border-[var(--border)] px-3 py-2 text-sm">File challenge</button></form></>}</div>
        </div>
        {asset.latestChallenge && <div className="mt-5 rounded-lg bg-[#080d15] p-4 text-sm"><p className="text-[var(--muted)]">Publish this value at <span className="text-white">{asset.latestChallenge.recordName}</span></p><code className="mt-2 block break-all text-[var(--accent)]">{asset.latestChallenge.verificationValue}</code><form action={verifyAssetAction} className="mt-3"><input type="hidden" name="assetId" value={asset._id}/><button className="rounded border border-emerald-300/30 px-3 py-1.5 text-[var(--accent)]">Check verification</button></form></div>}
        {asset.ownershipStatus !== "verified" && <details className="mt-4 rounded-lg border border-amber-300/20 bg-amber-300/5 p-4"><summary className="cursor-pointer text-sm font-medium text-amber-200">No DNS or website access?</summary><form action={authorizePassiveScanAction} className="mt-4 space-y-3"><input type="hidden" name="assetId" value={asset._id}/><p className="text-xs leading-5 text-[var(--muted)]">Use this only when you have permission or a legitimate assessment engagement. It enables passive checks only and records your attestation in the audit log.</p><textarea name="authorizationBasis" required minLength={10} maxLength={500} placeholder="Example: Written authorization from the website owner dated..." className="min-h-20 w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2 text-sm"/><label className="flex items-start gap-2 text-xs text-slate-300"><input type="checkbox" name="confirmed" value="yes" required className="mt-0.5"/><span>I confirm I am authorized to run a passive security assessment against this asset.</span></label><button className="rounded border border-amber-300/30 px-3 py-2 text-sm text-amber-200">Record authorization</button></form></details>}
      </article>)}
    </section>
  </div>;
}
