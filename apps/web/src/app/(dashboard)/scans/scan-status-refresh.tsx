"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export function ScanStatusRefresh({ active }: { active: boolean }) {
  const router = useRouter();

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => router.refresh(), 1_000);
    return () => window.clearInterval(timer);
  }, [active, router]);

  if (!active) return null;
  return <div className="mt-5 overflow-hidden rounded-xl border border-emerald-300/20 bg-emerald-300/5 p-4" role="status" aria-live="polite">
    <div className="flex items-center gap-3">
      <span className="relative flex size-9 items-center justify-center" aria-hidden="true">
        <span className="absolute size-9 animate-ping rounded-full border border-[var(--accent)] opacity-30" />
        <span className="absolute size-6 animate-pulse rounded-full bg-emerald-300/10" />
        <span className="size-2 rounded-full bg-[var(--accent)] shadow-[0_0_12px_var(--accent)]" />
      </span>
      <div><p className="text-sm font-medium text-[var(--accent)]">Passive assessment in progress</p><p className="mt-1 text-xs text-[var(--muted)]">Collecting DNS, certificates, RDAP, TLS and HTTP evidence. New results appear automatically.</p></div>
    </div>
    <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-white/5"><div className="scan-progress h-full w-1/3 rounded-full bg-[var(--accent)]" /></div>
  </div>;
}
