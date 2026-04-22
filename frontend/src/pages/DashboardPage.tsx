import { useEffect, useState } from 'react';

import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities as fallbackVulnerabilities } from '../services/mockData';
import { fetchScanTrends, fetchVulnerabilities } from '../services/platformApi';
import { ScanJob, Vulnerability } from '../types';

function DashboardPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(fallbackVulnerabilities);
  const [scanItems, setScanItems] = useState<ScanJob[]>(scanHistory);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [vulns, trends] = await Promise.all([fetchVulnerabilities(), fetchScanTrends()]);
        if (active) {
          setVulnerabilities(vulns);
          setScanItems(
            trends.map((point, idx) => ({
              id: `TREND-${idx + 1}`,
              target: point.day,
              status: 'completed',
              findings: point.findings,
              startedAt: point.day,
              duration: `${Math.round(point.avg_duration_ms)}ms avg`,
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
