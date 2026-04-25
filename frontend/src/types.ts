export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Vulnerability = {
  id: string;
  title: string;
  severity: Severity;
  status: 'open' | 'triaged' | 'fixed' | 'accepted_risk' | 'false_positive';
  cvss: number;
  endpoint: string;
  rule: string;
  explanation: string;
  impact: string;
  remediation: string;
  observedAt: string;
};

export type ScanJob = {
  id: string;
  target: string;
  status: 'completed' | 'running' | 'failed' | 'queued';
  findings: number;
  startedAt: string;
  duration: string;
  scanId?: string;
};

export type ScanRecord = {
  id: string;
  target: string;
  profile: 'quick' | 'standard' | 'deep';
  status: 'queued' | 'running' | 'completed' | 'failed' | 'reviewed';
  findings: number;
  createdAt: string;
  durationMs: number | null;
};

export type ScanTrendPoint = {
  day: string;
  scans: number;
  findings: number;
  avg_duration_ms: number;
};

export type FindingTimelineEvent = {
  event_type: string;
  message: string;
  created_at: string;
};
