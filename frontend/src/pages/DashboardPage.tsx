import { useEffect, useState } from 'react';

import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities as fallbackVulnerabilities } from '../services/mockData';
import { fetchScans, fetchVulnerabilities } from '../services/platformApi';
import { ScanJob, Vulnerability } from '../types';

function DashboardPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(fallbackVulnerabilities);
  const [scanItems, setScanItems] = useState<ScanJob[]>(scanHistory);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [vulns, scans] = await Promise.all([fetchVulnerabilities(), fetchScans(8)]);
        if (active) {
          setVulnerabilities(vulns);
          setScanItems(
            scans.map((scan) => ({
              id: scan.id,
              target: scan.target,
              status: scan.status === 'reviewed' ? 'completed' : scan.status,
              findings: scan.findings,
              startedAt: scan.createdAt,
              duration: scan.durationMs ? `${scan.durationMs}ms` : 'pending',
              scanId: scan.id,
            })),
          );
          setError(null);
        }
      } catch {
        if (active) {
          setError('Could not reach backend analytics. Showing demo data.');
        }
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, []);

  const critical = vulnerabilities.filter((v) => v.severity === 'critical').length;
  const open = vulnerabilities.filter((v) => v.status === 'open').length;

  return (
    <section className="stack">
      <PageHeader title="Threat Overview" subtitle="Real-time application security posture." />
      {error && <p className="notice warning">{error}</p>}
      <div className="metrics-grid">
        <MetricCard label="Open Vulnerabilities" value={open} detail="Requires triage" />
        <MetricCard label="Critical Findings" value={critical} detail="Immediate action" />
        <MetricCard label="Scan Trend Points" value={scanItems.length} detail="Recent activity window" />
      </div>

      <section className="card">
        <h3>Latest Vulnerabilities</h3>
        <VulnerabilityTable vulnerabilities={vulnerabilities} />
      </section>

      <section className="card">
        <h3>Recent Scan History</h3>
        <ScanHistoryList scans={scanItems} />
      </section>
    </section>
  );
}

export default DashboardPage;
