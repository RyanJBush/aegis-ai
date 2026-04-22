import { useEffect, useState } from 'react';

import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities as fallbackVulnerabilities } from '../services/mockData';
import { fetchVulnerabilities } from '../services/platformApi';
import { Vulnerability } from '../types';

function ScanResultsPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(fallbackVulnerabilities);
  const [notice, setNotice] = useState<string | null>('Use /reports/json or /reports/sarif endpoints for CI exports.');

  useEffect(() => {
    let active = true;
    void fetchVulnerabilities()
      .then((items) => {
        if (active) {
          setVulnerabilities(items);
          setNotice('Live vulnerability data loaded.');
        }
      })
      .catch(() => {
        if (active) {
          setNotice('Live API unavailable, showing demo dataset.');
        }
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <section className="stack">
      <PageHeader
        title="Scan Results"
        subtitle="Historical scans, current status, and discovered vulnerabilities."
      />
      {notice && <p className="notice">{notice}</p>}

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
