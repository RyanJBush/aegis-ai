import { useEffect, useState } from 'react';

import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities as fallbackVulnerabilities } from '../services/mockData';
import { downloadScanJsonReport, downloadScanSarifReport, fetchScans, fetchVulnerabilities } from '../services/platformApi';
import { ScanJob, Vulnerability } from '../types';

function ScanResultsPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(fallbackVulnerabilities);
  const [scanItems, setScanItems] = useState<ScanJob[]>(scanHistory);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>('Use the scan list to download JSON and SARIF reports.');

  useEffect(() => {
    let active = true;
    void Promise.all([fetchVulnerabilities(), fetchScans(20)])
      .then(([items, scans]) => {
        if (!active) return;
        setVulnerabilities(items);
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
        setSelectedScanId(scans[0]?.id ?? null);
        setNotice('Live scan and vulnerability data loaded.');
      })
      .catch(() => {
        if (active) {
          setNotice('Live API unavailable, showing demo dataset and disabling report export.');
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function exportJson() {
    if (!selectedScanId) return;
    try {
      await downloadScanJsonReport(selectedScanId);
      setNotice(`Downloaded JSON report for scan #${selectedScanId}.`);
    } catch {
      setNotice('Failed to export JSON report.');
    }
  }

  async function exportSarif() {
    if (!selectedScanId) return;
    try {
      await downloadScanSarifReport(selectedScanId);
      setNotice(`Downloaded SARIF report for scan #${selectedScanId}.`);
    } catch {
      setNotice('Failed to export SARIF report.');
    }
  }

  return (
    <section className="stack">
      <PageHeader
        title="Scan Results"
        subtitle="Historical scans, current status, and discovered vulnerabilities."
      />
      {notice && <p className="notice">{notice}</p>}

      <section className="card">
        <h3>Scan History</h3>
        <ScanHistoryList scans={scanItems} onSelectScan={setSelectedScanId} />
        <div className="report-actions">
          <p className="muted">Selected scan: {selectedScanId ? `#${selectedScanId}` : 'none'}</p>
          <button type="button" disabled={!selectedScanId} onClick={exportJson}>Export JSON</button>
          <button type="button" disabled={!selectedScanId} onClick={exportSarif}>Export SARIF</button>
        </div>
      </section>

      <section className="card">
        <h3>Detected Vulnerabilities</h3>
        <VulnerabilityTable vulnerabilities={vulnerabilities} />
      </section>
    </section>
  );
}

export default ScanResultsPage;
