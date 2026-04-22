import { getJson } from './api';
import { FindingTimelineEvent, ScanJob, ScanTrendPoint, Vulnerability } from '../types';

type RawVuln = {
  id: number;
  title: string;
  severity: Vulnerability['severity'];
  status: Vulnerability['status'];
  rule_key: string;
  owasp_category: string;
  remediation: string;
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

export async function fetchVulnerabilities(): Promise<Vulnerability[]> {
  const vulns = await getJson<RawVuln[]>('/vulnerabilities');
  return vulns.map((v) => ({
    id: String(v.id),
    title: v.title,
    severity: v.severity,
    status: v.status,
    cvss: severityToCvss(v.severity),
    endpoint: v.owasp_category,
    rule: v.rule_key,
    explanation: `${v.rule_key} matched scanner heuristics.`,
    impact: `Potential exploitation risk tied to ${v.owasp_category}.`,
    remediation: v.remediation,
    observedAt: v.created_at,
  }));
}

export async function fetchScanTrends(days = 14): Promise<ScanTrendPoint[]> {
  const response = await getJson<{ points: ScanTrendPoint[] }>(`/scanning/history/trends?days=${days}`);
  return response.points;
}

export async function queueScan(target: string, payload: string): Promise<ScanJob> {
  const response = await fetch(`${import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1'}/scanning/queue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, payload, profile: 'standard' }),
  });
  if (!response.ok) {
    throw new Error(`Queue scan failed (${response.status})`);
  }
  const job = (await response.json()) as RawScanJob;
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
  await postJson(`/vulnerabilities/${vulnId}/comments`, { body });
}

export async function acceptRisk(vulnId: string, reason: string): Promise<void> {
  await postJson(`/vulnerabilities/${vulnId}/risk-acceptance`, { reason });
}

async function postJson(path: string, body: unknown): Promise<void> {
  const response = await fetch(`${import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1'}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`);
  }
}

function mapJob(job: RawScanJob): ScanJob {
  return {
    id: String(job.id),
    target: job.scan_id ? `scan-${job.scan_id}` : 'queued target',
    status: job.status,
    findings: 0,
    startedAt: job.started_at ?? job.created_at,
    duration: job.completed_at ? 'done' : 'pending',
  };
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
