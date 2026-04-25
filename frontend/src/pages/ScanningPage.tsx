import { FormEvent, useState } from 'react';

import PageHeader from '../components/PageHeader';
import { getJob, queueScan, runScanNow } from '../services/platformApi';
import { ScanJob, ScanRecord } from '../types';

function ScanningPage() {
  const [target, setTarget] = useState('https://example.com');
  const [payload, setPayload] = useState("' OR 1=1 -- <script>alert(1)</script>");
  const [profile, setProfile] = useState<ScanRecord['profile']>('standard');
  const [job, setJob] = useState<ScanJob | null>(null);
  const [latestScan, setLatestScan] = useState<ScanRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleQueue(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const queued = await queueScan(target, payload);
      setJob(queued);
      setLatestScan(null);
    } catch {
      setError('Failed to queue scan. Ensure backend is running and authenticated context is configured.');
    } finally {
      setLoading(false);
    }
  }

  async function handleRunNow(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const scan = await runScanNow(target, payload, profile);
      setLatestScan(scan);
      setJob(null);
    } catch {
      setError('Failed to run scan. Ensure credentials and target URL are valid.');
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

      <form className="card form-card" onSubmit={handleRunNow}>
        <h3>Run Scan Now</h3>
        <label>
          Target
          <input value={target} onChange={(event) => setTarget(event.target.value)} />
        </label>
        <label>
          Payload / snippet
          <textarea rows={5} value={payload} onChange={(event) => setPayload(event.target.value)} />
        </label>
        <label>
          Profile
          <select value={profile} onChange={(event) => setProfile(event.target.value as ScanRecord['profile'])}>
            <option value="quick">Quick</option>
            <option value="standard">Standard</option>
            <option value="deep">Deep</option>
          </select>
        </label>
        <button type="submit" disabled={loading}>{loading ? 'Running…' : 'Run Immediate Scan'}</button>
      </form>

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

      {latestScan && (
        <section className="card">
          <h3>Latest Completed Scan</h3>
          <p>
            Scan #{latestScan.id} • <strong>{latestScan.status.toUpperCase()}</strong> •{' '}
            {latestScan.findings} findings • profile {latestScan.profile}
          </p>
          <p className="muted">Open Scan Results to export JSON/SARIF artifacts for this run.</p>
        </section>
      )}
    </section>
  );
}

export default ScanningPage;
