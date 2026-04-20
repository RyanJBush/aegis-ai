import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities } from '../services/mockData';

function DashboardPage() {
  const critical = vulnerabilities.filter((v) => v.severity === 'critical').length;
  const open = vulnerabilities.filter((v) => v.status === 'open').length;

  return (
    <section className="stack">
      <PageHeader title="Threat Overview" subtitle="Real-time application security posture." />
      <div className="metrics-grid">
        <MetricCard label="Open Vulnerabilities" value={open} detail="Requires triage" />
        <MetricCard label="Critical Findings" value={critical} detail="Immediate action" />
        <MetricCard label="Scans Today" value={scanHistory.length} detail="Across monitored apps" />
      </div>

      <section className="card">
        <h3>Latest Vulnerabilities</h3>
        <VulnerabilityTable vulnerabilities={vulnerabilities} />
      </section>

      <section className="card">
        <h3>Recent Scan History</h3>
        <ScanHistoryList scans={scanHistory} />
      </section>
    </section>
  );
}

export default DashboardPage;
