import { ScanJob, Vulnerability } from '../types';

export const vulnerabilities: Vulnerability[] = [
  {
    id: 'VULN-1001',
    title: 'SQL Injection in login query',
    severity: 'critical',
    status: 'open',
    cvss: 9.8,
    description: 'Detected SQL injection-like input patterns in demo login flow.',
    endpoint: '/api/v1/auth/login',
    owaspCategory: 'A03:2021-Injection',
    rule: 'SQLI-TAUTOLOGY',
    explanation: 'User-controlled input appears in SQL query without parameterization.',
    impact: 'Attackers may bypass authentication and extract database records.',
    remediation: 'Use parameterized queries and strict server-side validation.',
    observedAt: '2026-04-18T11:20:00Z',
  },
  {
    id: 'VULN-1002',
    title: 'Reflected XSS in search parameter',
    severity: 'high',
    status: 'triaged',
    cvss: 8.2,
    description: 'Detected script injection payload in reflected search results.',
    endpoint: '/search',
    owaspCategory: 'A03:2021-Injection',
    rule: 'XSS-SCRIPT-TAG',
    explanation: 'Search term is reflected into HTML without output encoding.',
    impact: 'Session theft and malicious script execution in victim browser.',
    remediation: 'Apply contextual output encoding and Content Security Policy.',
    observedAt: '2026-04-19T09:12:00Z',
  },
  {
    id: 'VULN-1003',
    title: 'Verbose error leakage',
    severity: 'medium',
    status: 'open',
    cvss: 5.6,
    description: 'Verbose error handling may leak sensitive implementation details.',
    endpoint: '/api/v1/scanning/run',
    owaspCategory: 'A05:2021-Security Misconfiguration',
    rule: 'INFO-DISCLOSURE',
    explanation: 'Unhandled errors expose stack traces with internal details.',
    impact: 'Assists attackers with reconnaissance and exploit development.',
    remediation: 'Return generic errors externally and keep details in logs only.',
    observedAt: '2026-04-19T10:04:00Z',
  },
];

export const scanHistory: ScanJob[] = [
  {
    id: 'SCAN-431',
    target: 'https://portal.example.com',
    status: 'completed',
    findings: 5,
    startedAt: '2026-04-19T08:00:00Z',
    duration: '03m 22s',
  },
  {
    id: 'SCAN-432',
    target: 'https://api.example.com',
    status: 'running',
    findings: 1,
    startedAt: '2026-04-20T01:50:00Z',
    duration: '01m 05s',
  },
  {
    id: 'SCAN-430',
    target: 'https://admin.example.com',
    status: 'failed',
    findings: 0,
    startedAt: '2026-04-18T22:19:00Z',
    duration: '00m 47s',
  },
];

export function getVulnerabilityById(id: string): Vulnerability | undefined {
  return vulnerabilities.find((v) => v.id === id);
}
