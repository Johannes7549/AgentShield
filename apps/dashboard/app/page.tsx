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
                <a
                  href={`#${area.id}`}
                  className="block rounded px-3 py-2 text-sm text-slate-200 hover:bg-ink"
                >
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
            <h1 className="text-base font-semibold">Foundation</h1>
            <p className="text-sm text-muted">Phase 0. Architecture status, not live telemetry.</p>
          </div>
          <p className="rounded border border-line px-2 py-1 font-mono text-xs text-accent">local</p>
        </header>
        <main className="space-y-10 px-6 py-8">
          <section aria-labelledby="services-heading">
            <h2 id="services-heading" className="text-lg font-semibold">
              What this revision runs
            </h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">
              The console shell is in place so later phases have a stable layout. It does not query
              agents, policies, or events, and it does not show placeholder counts.
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
          <section aria-labelledby="areas-heading">
            <h2 id="areas-heading" className="text-lg font-semibold">
              Planned sections
            </h2>
            <div className="mt-4 grid gap-3 lg:grid-cols-2">
              {areas.map((area) => (
                <article key={area.id} id={area.id} className="rounded border border-line bg-panel p-4">
                  <div className="flex items-baseline justify-between gap-3">
                    <h3 className="font-medium">{area.name}</h3>
                    <p className="font-mono text-xs text-accent">{area.phase}</p>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-muted">{area.status}</p>
                </article>
              ))}
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
