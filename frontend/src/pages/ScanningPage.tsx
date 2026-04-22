import { FormEvent, useState } from 'react';

import PageHeader from '../components/PageHeader';
import { getJob, queueScan } from '../services/platformApi';
import { ScanJob } from '../types';

function ScanningPage() {
  const [target, setTarget] = useState('https://example.internal');
  const [payload, setPayload] = useState("' OR 1=1 -- <script>alert(1)</script>");
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleQueue(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const queued = await queueScan(target, payload);
      setJob(queued);
    } catch {
      setError('Failed to queue scan. Ensure backend is running and authenticated context is configured.');
    } finally {
      setLoading(false);
    }
  }

  async function refreshJob() {
    if (!job) return;
    try {
      const refreshed = await getJob(job.id);
      setJob(refreshed);
    } catch {
      setError('Unable to refresh job state.');
    }
  }

  return (
    <section className="stack">
      <PageHeader title="Scan Ops" subtitle="Queue scans, monitor worker jobs, and consume CI export artifacts." />

      <form className="card form-card" onSubmit={handleQueue}>
        <h3>Queue New Scan Job</h3>
        <label>
          Target
          <input value={target} onChange={(event) => setTarget(event.target.value)} />
        </label>
        <label>
          Payload / snippet
          <textarea rows={5} value={payload} onChange={(event) => setPayload(event.target.value)} />
        </label>
        <button type="submit" disabled={loading}>{loading ? 'Queueing…' : 'Queue Scan'}</button>
      </form>

      {error && <p className="notice error">{error}</p>}

      {job && (
        <section className="card">
          <h3>Latest Job</h3>
          <p>Job #{job.id} • Status: <strong>{job.status}</strong></p>
          <button type="button" onClick={refreshJob}>Refresh Job Status</button>
          <p className="muted">When completed, use backend APIs to fetch `/reports/json` and `/reports/sarif`.</p>
        </section>
      )}
    </section>
  );
}

export default ScanningPage;
