import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities } from '../services/mockData';

function ScanResultsPage() {
  return (
    <section className="stack">
      <PageHeader
        title="Scan Results"
        subtitle="Historical scans, current status, and discovered vulnerabilities."
      />

      <section className="card">
        <h3>Scan History</h3>
        <ScanHistoryList scans={scanHistory} />
      </section>

      <section className="card">
        <h3>Detected Vulnerabilities</h3>
        <VulnerabilityTable vulnerabilities={vulnerabilities} />
      </section>
    </section>
  );
}

export default ScanResultsPage;
