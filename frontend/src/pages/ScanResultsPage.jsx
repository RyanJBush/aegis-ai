import { Link } from 'react-router-dom'

import SeverityBadge from '../components/SeverityBadge'

function ScanResultsPage({ vulnerabilities, runScan, scanForm, setScanForm }) {
  return (
    <section className="space-y-6">
      <h2 className="text-2xl font-semibold">Scan Results</h2>
      <form
        className="space-y-3 rounded border border-slate-800 bg-slate-900 p-4"
        onSubmit={runScan}
      >
        <input
          className="w-full rounded bg-slate-800 p-2"
          placeholder="Target"
          value={scanForm.target}
          onChange={(event) =>
            setScanForm((prev) => ({ ...prev, target: event.target.value }))
          }
          required
        />
        <textarea
          className="min-h-32 w-full rounded bg-slate-800 p-2"
          placeholder="Content to scan"
          value={scanForm.content}
          onChange={(event) =>
            setScanForm((prev) => ({ ...prev, content: event.target.value }))
          }
          required
        />
        <button className="rounded bg-blue-600 px-4 py-2" type="submit">
          Run Scan
        </button>
      </form>

      <div className="overflow-hidden rounded border border-slate-800 bg-slate-900">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-800 text-slate-300">
            <tr>
              <th className="p-3">ID</th>
              <th className="p-3">Title</th>
              <th className="p-3">Severity</th>
              <th className="p-3">Action</th>
            </tr>
          </thead>
          <tbody>
            {vulnerabilities.map((vuln) => (
              <tr key={vuln.id} className="border-t border-slate-800">
                <td className="p-3">{vuln.id}</td>
                <td className="p-3">{vuln.title}</td>
                <td className="p-3">
                  <SeverityBadge severity={vuln.severity} />
                </td>
                <td className="p-3">
                  <Link
                    className="text-blue-300"
                    to={`/vulnerabilities/${vuln.id}`}
                  >
                    View details
                  </Link>
                </td>
              </tr>
            ))}
            {!vulnerabilities.length ? (
              <tr>
                <td className="p-3 text-slate-400" colSpan={4}>
                  No vulnerabilities to display.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default ScanResultsPage
