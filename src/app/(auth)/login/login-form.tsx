"use client";

import { useActionState } from "react";
import { loginAction } from "./actions";

export function LoginForm() {
  const [state, action, pending] = useActionState(loginAction, undefined);
  return (
    <form action={action} className="mt-8 space-y-5">
      <div>
        <label className="mb-2 block text-sm text-slate-300" htmlFor="email">Admin email</label>
        <input className="w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-4 py-3 outline-none transition focus:border-[var(--accent)] focus:ring-2 focus:ring-emerald-400/10" id="email" name="email" type="email" autoComplete="username" required autoFocus />
      </div>
      <div>
        <label className="mb-2 block text-sm text-slate-300" htmlFor="password">Password</label>
        <input className="w-full rounded-lg border border-[var(--border)] bg-[#080d15] px-4 py-3 outline-none transition focus:border-[var(--accent)] focus:ring-2 focus:ring-emerald-400/10" id="password" name="password" type="password" autoComplete="current-password" required />
      </div>
      {state?.error && <p role="alert" className="rounded-lg border border-red-400/20 bg-red-400/5 px-4 py-3 text-sm text-[var(--danger)]">{state.error}</p>}
      <button disabled={pending} className="w-full rounded-lg bg-[var(--accent)] px-4 py-3 font-semibold text-[#04110c] transition hover:brightness-110 disabled:cursor-wait disabled:opacity-60" type="submit">
        {pending ? "Authenticating…" : "Sign in securely"}
      </button>
    </form>
  );
}
