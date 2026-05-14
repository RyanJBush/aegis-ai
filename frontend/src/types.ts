export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type CVEMatch = { cve_id: string; cvss_v3_base_score?: number | null; severity?: string | null; description: string; nvd_url: string; };
export type RemediationTemplate = { description: string; code_example: string; reference_url: string; };

export type Vulnerability = {
  id: string;
  scanId?: string;
  title: string;
  severity: Severity;
  status: 'open' | 'in_progress' | 'resolved' | 'triaged' | 'fixed' | 'accepted_risk' | 'false_positive';
  cvss: number;
  description: string;
  endpoint: string;
  owaspCategory?: string;
  rule: string;
  explanation: string;
  impact: string;
  remediation: string;
  remediationTemplate?: RemediationTemplate | null;
  cveMatches?: CVEMatch[];
  confidence?: number;
  reasonCode?: string;
  cweId?: string;
  evidence?: string;
  exampleRequest?: string;
  exampleResponse?: string;
  secureExample?: string;
  assignedOwner?: string | null;
  notes?: string | null;
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

export type KpiSummary = {
  total_findings: number;
  critical_findings: number;
  high_severity_findings: number;
  open_findings: number;
  resolved_findings: number;
  fixed_findings: number;
  scan_coverage_percent: number;
  average_scan_time_ms: number;
};

export type AuditLogEntry = {
  id: number;
  action: string;
  entity_type: string;
  entity_id?: number | null;
  actor_user_id?: number | null;
  created_at: string;
  details?: Record<string, unknown> | null;
};

export type RuleChangeEntry = {
  id: number;
  rule_key: string;
  change_type: string;
  reason?: string | null;
  actor_user_id: number;
  created_at: string;
};
