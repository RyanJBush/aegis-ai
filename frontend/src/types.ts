export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Vulnerability = {
  id: string;
  title: string;
  severity: Severity;
  status: 'open' | 'triaged' | 'resolved';
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
  status: 'completed' | 'running' | 'failed';
  findings: number;
  startedAt: string;
  duration: string;
};
