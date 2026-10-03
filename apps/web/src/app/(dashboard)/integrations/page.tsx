import type { Metadata } from "next";
import { listIntegrations } from "@/server/integrations/service";
import { createIntegrationAction, deleteIntegrationAction, testIntegrationAction } from "./actions";

export const metadata: Metadata = { title: "Integrations" };

export default async function IntegrationsPage({ searchParams }: { searchParams: Promise<{ message?: string; error?: string }> }) {
  const [params, integrations] = await Promise.all([searchParams, listIntegrations()]);
  return <div className="mx-auto max-w-6xl">
    <p className="text-sm font-medium text-[var(--accent)]">AUTOMATION</p><h1 className="mt-2 text-3xl font-semibold">Integrations</h1><p className="mt-2 text-[var(--muted)]">Deliver critical and high findings to collaboration, ticketing, webhook, or SIEM endpoints.</p>
    {(params.message || params.error) && <p className={`mt-6 rounded-lg border px-4 py-3 text-sm ${params.error ? "border-red-400/20 text-[var(--danger)]" : "border-emerald-300/20 text-[var(--accent)]"}`}>{params.error ?? params.message}</p>}
    <form action={createIntegrationAction} className="mt-7 grid gap-4 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 md:grid-cols-2">
      <label className="text-sm">Name<input name="name" required className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2" /></label>
      <label className="text-sm">Type<select name="type" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2"><option value="slack">Slack</option><option value="teams">Microsoft Teams</option><option value="webhook">Signed webhook</option><option value="siem">SIEM webhook</option><option value="jira">Jira Cloud</option><option value="servicenow">ServiceNow</option></select></label>
      <label className="text-sm md:col-span-2">HTTPS endpoint or base URL<input name="endpoint" type="url" required placeholder="https://..." className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2" /></label>
      <label className="text-sm">Username / Jira email<input name="username" autoComplete="off" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2" /></label>
      <label className="text-sm">Secret / API token<input name="secret" type="password" autoComplete="new-password" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2" /></label>
      <label className="text-sm">Jira project key<input name="projectKey" className="mt-2 block w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-3 py-2" /></label>
      <button className="self-end rounded-lg bg-[var(--accent)] px-4 py-2 font-medium text-[#04120d]">Save integration</button>
    </form>
    <div className="mt-6 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
      {integrations.length === 0 && <p className="p-10 text-center text-[var(--muted)]">No integrations configured.</p>}
      {integrations.map((item) => <div key={item._id.toHexString()} className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border)] px-5 py-4 last:border-0"><div><p className="font-medium">{item.name}</p><p className="mt-1 text-xs text-[var(--muted)]">{item.type} · Latest: {item.latestDelivery?.status ?? "never tested"}</p></div><div className="flex gap-2"><form action={testIntegrationAction}><input type="hidden" name="integrationId" value={item._id.toHexString()} /><button className="rounded border border-[var(--border)] px-3 py-2 text-sm">Test</button></form><form action={deleteIntegrationAction}><input type="hidden" name="integrationId" value={item._id.toHexString()} /><button className="rounded border border-red-400/20 px-3 py-2 text-sm text-[var(--danger)]">Remove</button></form></div></div>)}
    </div>
  </div>;
}
