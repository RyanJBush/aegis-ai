import { getJson, patchJson as patchJsonRequest, postJson as postJsonRequest } from './api';
import { FindingTimelineEvent, KpiSummary, ScanJob, ScanRecord, ScanTrendPoint, Vulnerability } from '../types';

type RawVuln = {
  id: number;
  scan_id: number;
  title: string;
  severity: Vulnerability['severity'];
  status: Vulnerability['status'];
  rule_key: string;
  owasp_category: string;
  confidence: number;
  reason_code: string;
  cwe_id: string;
  evidence: string;
  remediation: string;
  secure_example?: string | null;
  assigned_owner?: string | null;
  notes?: string | null;
  created_at: string;
};

type RawScanJob = {
  id: number;
  scan_id?: number | null;
  status: ScanJob['status'];
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
};

type RawScanRecord = {
  id: number;
  target: string;
  profile: ScanRecord['profile'];
  status: ScanRecord['status'];
  created_at: string;
  duration_ms: number | null;
  vulnerabilities_found: number;
};

type RawScanResponse = RawScanRecord;

type JsonReport = {
  scan_id: number;
  generated_at: string;
  findings: Array<{
    id: number;
    title: string;
    severity: string;
    status: string;
    owasp: string;
    cwe: string;
    dedupe_key: string;
  }>;
};

type SarifReport = {
  scan_id: number;
  sarif: Record<string, unknown>;
};

export async function fetchVulnerabilities(): Promise<Vulnerability[]> {
  const vulns = await getJson<RawVuln[]>('/vulnerabilities');
  return vulns.map(mapRawVulnerability);
}

export async function fetchVulnerabilityById(vulnId: string): Promise<Vulnerability> {
  const vuln = await getJson<RawVuln>(`/vulnerabilities/${vulnId}`);
  return mapRawVulnerability(vuln);
}

export async function fetchScanTrends(days = 14): Promise<ScanTrendPoint[]> {
  const response = await getJson<{ points: ScanTrendPoint[] }>(`/scanning/history/trends?days=${days}`);
  return response.points;
}

export async function fetchKpiSummary(): Promise<KpiSummary> {
  return getJson<KpiSummary>('/scanning/kpi/summary');
}

export async function fetchScans(limit = 30): Promise<ScanRecord[]> {
  const scans = await getJson<RawScanRecord[]>(`/scanning?limit=${limit}&offset=0&sort_dir=desc`);
  return scans.map(mapScanRecord);
}

export async function runScanNow(
  target: string,
  payload: string,
  profile: ScanRecord['profile'],
): Promise<ScanRecord> {
  const scan = await postJsonRequest<RawScanResponse, { target: string; payload: string; profile: ScanRecord['profile'] }>(
    '/scanning/run',
    { target, payload, profile },
  );
  return mapScanRecord(scan);
}

export async function queueScan(target: string, payload: string): Promise<ScanJob> {
  const job = await postJsonRequest<RawScanJob, { target: string; payload: string; profile: string }>(
    '/scanning/queue',
    { target, payload, profile: 'standard' },
  );
  return mapJob(job);
}

export async function getJob(jobId: string): Promise<ScanJob> {
  const job = await getJson<RawScanJob>(`/scanning/jobs/${jobId}`);
  return mapJob(job);
}

export async function getFindingTimeline(vulnId: string): Promise<FindingTimelineEvent[]> {
  const timeline = await getJson<{ events: FindingTimelineEvent[] }>(`/vulnerabilities/${vulnId}/timeline`);
  return timeline.events;
}

export async function addFindingComment(vulnId: string, body: string): Promise<void> {
  await postJsonRequest<Record<string, never>, { body: string }>(`/vulnerabilities/${vulnId}/comments`, { body });
}

export async function updateFindingWorkflow(
  vulnId: string,
  payload: { status: Vulnerability['status']; assigned_owner?: string | null; notes?: string | null },
): Promise<Vulnerability> {
  const vuln = await patchJsonRequest<RawVuln, { status: Vulnerability['status']; assigned_owner?: string | null; notes?: string | null }>(
    `/vulnerabilities/${vulnId}/workflow`,
    payload,
  );
  return mapRawVulnerability(vuln);
}

export async function acceptRisk(vulnId: string, reason: string): Promise<void> {
  await postJsonRequest<Record<string, never>, { reason: string }>(
    `/vulnerabilities/${vulnId}/risk-acceptance`,
    { reason },
  );
}

function mapRawVulnerability(vuln: RawVuln): Vulnerability {
  return {
    id: String(vuln.id),
    scanId: String(vuln.scan_id),
    title: vuln.title,
    severity: vuln.severity,
    status: vuln.status,
    cvss: severityToCvss(vuln.severity),
    endpoint: vuln.owasp_category,
    rule: vuln.rule_key,
    explanation: `${vuln.rule_key} matched scanner heuristics with ${Math.round(vuln.confidence * 100)}% confidence.`,
    impact: `Potential exploitation risk tied to ${vuln.owasp_category}.`,
    remediation: vuln.remediation,
    confidence: vuln.confidence,
    reasonCode: vuln.reason_code,
    cweId: vuln.cwe_id,
    evidence: vuln.evidence,
    secureExample: vuln.secure_example ?? undefined,
    assignedOwner: vuln.assigned_owner ?? null,
    notes: vuln.notes ?? null,
    observedAt: vuln.created_at,
  };
}

function mapJob(job: RawScanJob): ScanJob {
  return {
    id: String(job.id),
    target: job.scan_id ? `scan-${job.scan_id}` : 'queued target',
    status: job.status,
    findings: 0,
    startedAt: job.started_at ?? job.created_at,
    duration: job.completed_at ? 'done' : 'pending',
    scanId: job.scan_id ? String(job.scan_id) : undefined,
  };
}

export async function downloadScanJsonReport(scanId: string): Promise<void> {
  const report = await getJson<JsonReport>(`/scanning/${scanId}/reports/json`);
  downloadFile(`scan-${scanId}-report.json`, JSON.stringify(report, null, 2));
}

export async function downloadScanSarifReport(scanId: string): Promise<void> {
  const report = await getJson<SarifReport>(`/scanning/${scanId}/reports/sarif`);
  downloadFile(`scan-${scanId}-report.sarif.json`, JSON.stringify(report.sarif, null, 2));
}

function mapScanRecord(scan: RawScanRecord): ScanRecord {
  return {
    id: String(scan.id),
    target: scan.target,
    profile: scan.profile,
    status: scan.status,
    findings: scan.vulnerabilities_found,
    createdAt: scan.created_at,
    durationMs: scan.duration_ms,
  };
}

function downloadFile(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function severityToCvss(severity: Vulnerability['severity']): number {
  switch (severity) {
    case 'critical':
      return 9.8;
    case 'high':
      return 8.1;
    case 'medium':
      return 5.5;
    default:
      return 3.1;
  }
}
