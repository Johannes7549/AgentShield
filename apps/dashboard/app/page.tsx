import { LiveConsole } from "../components/live-console";
import { areas, services } from "../lib/inventory";

export default function HomePage() {
  return (
    <div className="min-h-screen md:grid md:grid-cols-[240px_1fr]">
      <aside className="border-b border-line bg-panel md:border-b-0 md:border-r">
        <div className="px-5 py-6">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">AgentShield</p>
          <p className="mt-2 text-lg font-semibold">Security operations</p>
        </div>
        <nav aria-label="Console sections" className="px-3 pb-6">
          <ul className="space-y-1">
            {areas.map((area) => (
              <li key={area.id}>
                <a href={`#${area.id}`} className="block rounded px-3 py-2 text-sm text-slate-200 hover:bg-ink">
                  {area.name}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <div>
        <header className="flex items-center justify-between border-b border-line px-6 py-4">
          <div>
            <h1 className="text-base font-semibold">Operations</h1>
            <p className="text-sm text-muted">Phase 6. Live control-plane reads, not invented metrics.</p>
          </div>
          <p className="rounded border border-line px-2 py-1 font-mono text-xs text-accent">local</p>
        </header>
        <main className="space-y-10 px-6 py-8">
          <section aria-labelledby="services-heading">
            <h2 id="services-heading" className="text-lg font-semibold">
              What this revision runs
            </h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">
              The console loads agents, incidents, events, and audit links from the control plane after sign-in. It
              refreshes on an interval and can export a copy of the audit head.
            </p>
            <div className="mt-4 overflow-hidden rounded border border-line">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Service readiness</caption>
                <thead className="bg-panel text-muted">
                  <tr>
                    <th className="px-4 py-3 font-medium" scope="col">
                      Service
                    </th>
                    <th className="px-4 py-3 font-medium" scope="col">
                      Address
                    </th>
                    <th className="px-4 py-3 font-medium" scope="col">
                      Readiness
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {services.map((service) => (
                    <tr key={service.name} className="border-t border-line">
                      <th className="px-4 py-3 font-medium" scope="row">
                        {service.name}
                      </th>
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">{service.address}</td>
                      <td className="px-4 py-3 text-slate-300">{service.readiness}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <LiveConsole />
        </main>
      </div>
    </div>
  );
}
