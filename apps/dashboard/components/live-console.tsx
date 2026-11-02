"use client";

import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { FormEvent, useMemo, useState } from "react";
import { areas } from "../lib/inventory";

const client = new QueryClient();

export function LiveConsole() {
  return (
    <QueryClientProvider client={client}>
      <ConsoleBody />
    </QueryClientProvider>
  );
}

function ConsoleBody() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [signedIn, setSignedIn] = useState(false);
  const [authError, setAuthError] = useState("");

  const overview = useQuery({
    queryKey: ["overview", signedIn],
    enabled: true,
    refetchInterval: 5000,
    queryFn: async () => {
      const [agents, incidents, events, audit] = await Promise.all([
        fetchJson<{ items: { id: string; status: string }[] }>("/api/control/v1/agents"),
        fetchJson<{ items: { id: string; severity: string; status: string }[] }>("/api/control/v1/incidents"),
        fetchJson<{ items: { id: string; event_type: string; occurred_at: string }[] }>("/api/control/v1/events?limit=20"),
        fetchJson<{ items: { sequence: number; event_hash: string }[] }>("/api/control/v1/audit"),
      ]);
      return { agents, incidents, events, audit };
    },
  });

  const bars = useMemo(() => {
    const items = overview.data?.events.items ?? [];
    const counts = new Map<string, number>();
    for (const item of items) {
      counts.set(item.event_type, (counts.get(item.event_type) ?? 0) + 1);
    }
    const max = Math.max(1, ...counts.values());
    return [...counts.entries()].map(([name, value]) => ({ name, value, width: `${Math.round((value / max) * 100)}%` }));
  }, [overview.data]);

  async function onSignIn(event: FormEvent): Promise<void> {
    event.preventDefault();
    setAuthError("");
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) {
      setAuthError("sign-in failed");
      return;
    }
    setSignedIn(true);
    await overview.refetch();
  }

  async function onSignOut(): Promise<void> {
    await fetch("/api/session", { method: "DELETE" });
    setSignedIn(false);
  }

  async function exportHead(): Promise<void> {
    await fetch("/api/control/v1/audit/exports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ destination: "dashboard-local-copy" }),
    });
    await overview.refetch();
  }

  const unauthorized = overview.isError || (overview.data === undefined && overview.isFetched);

  return (
    <div className="space-y-10">
      <section className="rounded border border-line bg-panel p-4">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold">Operator session</h2>
            <p className="mt-1 text-sm text-muted">The console calls the control plane through this process. It does not hold agent keys.</p>
          </div>
          {signedIn ? (
            <button type="button" onClick={onSignOut} className="rounded border border-line px-3 py-2 text-sm">
              Sign out
            </button>
          ) : (
            <form onSubmit={onSignIn} className="flex flex-wrap gap-2">
              <input
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="owner@example.com"
                className="rounded border border-line bg-ink px-3 py-2 text-sm"
              />
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="password"
                className="rounded border border-line bg-ink px-3 py-2 text-sm"
              />
              <button type="submit" className="rounded border border-accent px-3 py-2 text-sm text-accent">
                Sign in
              </button>
            </form>
          )}
        </div>
        {authError ? <p className="mt-2 text-sm text-rose-300">{authError}</p> : null}
        {unauthorized && !signedIn ? (
          <p className="mt-2 text-sm text-muted">Sign in to load live counts. Without a session the panels stay empty.</p>
        ) : null}
      </section>

      <section className="grid gap-3 md:grid-cols-4">
        <Stat label="Agents" value={overview.data?.agents.items.length ?? 0} />
        <Stat label="Open incidents" value={(overview.data?.incidents.items ?? []).filter((item) => item.status === "open").length} />
        <Stat label="Recent events" value={overview.data?.events.items.length ?? 0} />
        <Stat label="Audit links" value={overview.data?.audit.items.length ?? 0} />
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <article className="rounded border border-line bg-panel p-4">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Event mix</h2>
            <p className="font-mono text-xs text-accent">live</p>
          </div>
          <div className="mt-4 space-y-3">
            {bars.length === 0 ? <p className="text-sm text-muted">No events yet.</p> : null}
            {bars.map((bar) => (
              <div key={bar.name}>
                <div className="mb-1 flex justify-between text-xs text-muted">
                  <span>{bar.name}</span>
                  <span>{bar.value}</span>
                </div>
                <div className="h-2 rounded bg-ink">
                  <div className="h-2 rounded bg-accent" style={{ width: bar.width }} />
                </div>
              </div>
            ))}
          </div>
        </article>
        <article className="rounded border border-line bg-panel p-4">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Audit head</h2>
            <button type="button" onClick={exportHead} className="rounded border border-line px-2 py-1 text-xs">
              Export copy
            </button>
          </div>
          <ul className="mt-4 space-y-2 font-mono text-xs text-slate-300">
            {(overview.data?.audit.items ?? []).slice(0, 5).map((item) => (
              <li key={`${item.sequence}-${item.event_hash}`}>
                #{item.sequence} {item.event_hash.slice(0, 16)}…
              </li>
            ))}
          </ul>
        </article>
      </section>

      <section className="grid gap-3 lg:grid-cols-2">
        {areas.map((area) => (
          <article key={area.id} id={area.id} className="rounded border border-line bg-panel p-4">
            <div className="flex items-baseline justify-between gap-3">
              <h3 className="font-medium">{area.name}</h3>
              <p className="font-mono text-xs text-accent">{area.phase}</p>
            </div>
            <p className="mt-2 text-sm leading-6 text-muted">{area.status}</p>
          </article>
        ))}
      </section>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <article className="rounded border border-line bg-panel p-4">
      <p className="text-xs uppercase tracking-[0.14em] text-muted">{label}</p>
      <p className="mt-2 font-mono text-2xl text-slate-100">{value}</p>
    </article>
  );
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}
