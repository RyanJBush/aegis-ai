import { FormEvent, useState } from 'react';

import PageHeader from '../components/PageHeader';
import { postJson } from '../services/api';

type ScanResponse = {
  id: number;
  status: string;
  vulnerabilities_found: number;
};

function AppInterfacePage() {
  const [target, setTarget] = useState('https://app.example.com/login');
  const [payload, setPayload] = useState(`' OR 1=1 --\n<script>alert(1)</script>`);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleRunScan(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setNotice(null);
    try {
      const response = await postJson<ScanResponse, { target: string; payload: string; profile: string }>(
        '/scanning/run',
        { target, payload, profile: 'standard' },
      );
      setResult(response);
      setNotice('Scan completed successfully.');
    } catch {
      setNotice('Scan execution failed. Ensure you are logged in with security analyst/admin privileges.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="stack">
      <PageHeader
        title="App Interface"
        subtitle="Simulate suspicious request payloads against monitored endpoints."
      />
      {notice && <p className="notice">{notice}</p>}
      <form className="card form-card" onSubmit={handleRunScan}>
        <label htmlFor="target">Target URL</label>
        <input
          id="target"
          type="url"
          placeholder="https://app.example.com/login"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
        />

        <label htmlFor="payload">Payload</label>
        <textarea
          id="payload"
          rows={8}
          placeholder={`' OR 1=1 --\n<script>alert(1)</script>`}
          value={payload}
          onChange={(event) => setPayload(event.target.value)}
        />

        <button type="submit" disabled={loading}>{loading ? 'Running…' : 'Run Security Scan'}</button>
        {result && (
          <small>
            Scan #{result.id} finished with status <strong>{result.status}</strong> and{' '}
            <strong>{result.vulnerabilities_found}</strong> findings.
          </small>
        )}
      </form>
    </section>
  );
}

export default AppInterfacePage;
