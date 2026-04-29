import { useEffect, useState } from 'react';

import PageHeader from '../components/PageHeader';
import ScanHistoryList from '../components/ScanHistoryList';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { scanHistory, vulnerabilities as fallbackVulnerabilities } from '../services/mockData';
import {
  downloadScanJsonReport,
  downloadScanSarifReport,
  fetchRemediationChecklist,
  fetchScans,
  fetchSuppressions,
  fetchVulnerabilities,
} from '../services/platformApi';
import { downloadScanJsonReport, downloadScanSarifReport, fetchScans, fetchVulnerabilities } from '../services/platformApi';
import { ScanJob, Vulnerability } from '../types';

function ScanResultsPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(fallbackVulnerabilities);
  const [scanItems, setScanItems] = useState<ScanJob[]>(scanHistory);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [checklist, setChecklist] = useState<string[]>([]);
  const [suppressionKeys, setSuppressionKeys] = useState<string[]>([]);
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

  async function loadRemediationData() {
    if (!selectedScanId) return;
    try {
      const [remediationChecklist, suppressions] = await Promise.all([
        fetchRemediationChecklist(selectedScanId),
        fetchSuppressions(selectedScanId),
      ]);
      setChecklist(remediationChecklist);
      setSuppressionKeys(suppressions);
      setNotice(`Loaded remediation checklist and suppressions for scan #${selectedScanId}.`);
    } catch {
      setNotice('Failed to load remediation checklist/suppressions.');
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
          <button type="button" disabled={!selectedScanId} onClick={loadRemediationData}>Load Remediation Data</button>
        </div>
      </section>

      {(checklist.length > 0 || suppressionKeys.length > 0) && (
        <section className="card">
          <h3>Remediation & Suppression Insights</h3>
          {checklist.length > 0 && (
            <>
              <h4>Remediation Checklist</h4>
              <ul>
                {checklist.map((item, index) => (
                  <li key={`${item}-${index}`}>{item}</li>
                ))}
              </ul>
            </>
          )}
          {suppressionKeys.length > 0 && (
            <>
              <h4>Suppression Keys</h4>
              <ul className="suppression-list">
                {suppressionKeys.map((key) => (
                  <li key={key}>{key}</li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}

      <section className="card">
        <h3>Detected Vulnerabilities</h3>
        <VulnerabilityTable vulnerabilities={vulnerabilities} />
      </section>
    </section>
  );
}

export default ScanResultsPage;
