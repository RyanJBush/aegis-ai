import { useEffect, useMemo, useState } from 'react';

import PageHeader from '../components/PageHeader';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { vulnerabilities as fallbackVulnerabilities } from '../services/mockData';
import { fetchVulnerabilities } from '../services/platformApi';
import { Vulnerability } from '../types';

function RemediationQueuePage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const items = await fetchVulnerabilities();
        if (active) {
          setVulnerabilities(items);
          setError(null);
        }
      } catch {
        if (active) {
          setVulnerabilities(fallbackVulnerabilities);
          setError('Live API unavailable. Showing seeded remediation queue.');
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, []);

  const openItems = useMemo(
    () => vulnerabilities.filter((v) => ['open', 'triaged', 'accepted_risk'].includes(v.status)),
    [vulnerabilities],
  );

  return (
    <section className="stack">
      <PageHeader
        title="Remediation Queue"
        subtitle="Triage and assign open findings with risk acceptance visibility."
      />
      {error && <p className="notice warning">{error}</p>}
      {loading ? (
        <section className="card">Loading remediation queue…</section>
      ) : (
        <section className="card">
          <h3>Open / Triaged / Accepted Risk</h3>
          <VulnerabilityTable vulnerabilities={openItems} />
        </section>
      )}
    </section>
  );
}

export default RemediationQueuePage;
