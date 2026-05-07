import { useEffect, useState } from 'react';

import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities as fallbackVulnerabilities } from '../services/mockData';
import { fetchKpiSummary, fetchScans, fetchScanTrends, fetchVulnerabilities } from '../services/platformApi';
import { KpiSummary, ScanJob, ScanTrendPoint, Vulnerability } from '../types';

function DashboardPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(fallbackVulnerabilities);
  const [scanItems, setScanItems] = useState<ScanJob[]>(scanHistory);
  const [kpi, setKpi] = useState<KpiSummary | null>(null);
  const [trendPoints, setTrendPoints] = useState<ScanTrendPoint[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [vulns, scans, summary, trends] = await Promise.all([
          fetchVulnerabilities(),
          fetchScans(8),
          fetchKpiSummary(),
          fetchScanTrends(10),
        ]);
        if (active) {
          setVulnerabilities(vulns);
          setKpi(summary);
          setTrendPoints(trends);
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
  const open = vulnerabilities.filter((v) => ['open', 'in_progress', 'triaged'].includes(v.status)).length;
  const resolved = vulnerabilities.filter((v) => ['resolved', 'fixed'].includes(v.status)).length;
  const total = vulnerabilities.length;
  const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  vulnerabilities.forEach((v) => { severityCounts[v.severity] = (severityCounts[v.severity] ?? 0) + 1; });
  const maxSeverityCount = Math.max(1, ...Object.values(severityCounts));
  const maxTrendFindings = Math.max(1, ...trendPoints.map((point) => point.findings));

  return (
    <section className="stack">
      <PageHeader title="Threat Overview" subtitle="Real-time application security posture." />
      {error && <p className="notice warning">{error}</p>}
      <div className="metrics-grid">
        <MetricCard label="Total Vulnerabilities" value={kpi?.total_findings ?? total} detail="Current finding inventory" />
        <MetricCard label="Critical Issues" value={kpi?.critical_findings ?? critical} detail="Immediate action required" />
        <MetricCard label="Resolved Issues" value={kpi?.resolved_findings ?? kpi?.fixed_findings ?? resolved} detail="Closed by remediation" />
        <MetricCard label="Open Findings" value={kpi?.open_findings ?? open} detail="Requires triage or fix" />
        <MetricCard
          label="OWASP Coverage"
          value={`${kpi?.scan_coverage_percent ?? 0}%`}
          detail="Categories touched"
        />
        <MetricCard
          label="Avg Scan Time"
          value={`${Math.round(kpi?.average_scan_time_ms ?? 0)}ms`}
          detail="Operational performance"
        />
      </div>

      <section className="card">
        <h3>Vulnerabilities by Severity</h3>
        <div className="trend-bars">
          {Object.entries(severityCounts).map(([severity, count]) => (
            <div key={severity} className="trend-row">
              <span className="trend-label">{severity.toUpperCase()}</span>
              <div className="trend-track">
                <div className={`trend-fill trend-${severity}`} style={{ width: `${(count / maxSeverityCount) * 100}%` }} />
              </div>
              <span className="trend-value">{count}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <h3>Vulnerabilities Over Time</h3>
        <div className="trend-bars">
          {trendPoints.slice(-8).map((point) => (
            <div key={point.day} className="trend-row">
              <span className="trend-label">{point.day.slice(5)}</span>
              <div className="trend-track">
                <div className="trend-fill trend-medium" style={{ width: `${(point.findings / maxTrendFindings) * 100}%` }} />
              </div>
              <span className="trend-value">{point.findings}</span>
            </div>
          ))}
        </div>
      </section>

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
