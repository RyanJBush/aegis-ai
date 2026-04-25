function DashboardPage({ me, vulnerabilities }) {
  const bySeverity = vulnerabilities.reduce(
    (acc, vuln) => ({ ...acc, [vuln.severity]: (acc[vuln.severity] ?? 0) + 1 }),
    {},
  )

  return (
    <section className="space-y-6">
      <h2 className="text-2xl font-semibold">Dashboard</h2>
      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded border border-slate-800 bg-slate-900 p-4">
          <h3 className="text-sm text-slate-400">User</h3>
          <p className="text-lg font-semibold">{me?.username ?? 'Unknown'}</p>
          <p className="text-sm uppercase text-slate-300">
            Role: {me?.role ?? '-'}
          </p>
        </div>
        <div className="rounded border border-slate-800 bg-slate-900 p-4">
          <h3 className="text-sm text-slate-400">Total vulnerabilities</h3>
          <p className="text-2xl font-semibold">{vulnerabilities.length}</p>
        </div>
        <div className="rounded border border-slate-800 bg-slate-900 p-4">
          <h3 className="text-sm text-slate-400">Critical findings</h3>
          <p className="text-2xl font-semibold text-rose-300">
            {bySeverity.critical ?? 0}
          </p>
        </div>
      </div>
      <div className="rounded border border-slate-800 bg-slate-900 p-4">
        <h3 className="mb-3 font-semibold">Scan results visualization</h3>
        <div className="space-y-2">
          {['critical', 'high', 'medium', 'low'].map((severity) => {
            const count = bySeverity[severity] ?? 0
            const width = vulnerabilities.length
              ? (count / vulnerabilities.length) * 100
              : 0
            return (
              <div key={severity}>
                <div className="mb-1 flex justify-between text-xs uppercase text-slate-300">
                  <span>{severity}</span>
                  <span>{count}</span>
                </div>
                <div className="h-2 rounded bg-slate-800">
                  <div
                    className="h-2 rounded bg-blue-500"
                    style={{ width: `${width}%` }}
                  ></div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}

export default DashboardPage
