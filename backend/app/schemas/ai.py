from pydantic import BaseModel


class ProvenanceItem(BaseModel):
    kind: str
    value: str


class FindingAIInsight(BaseModel):
    vulnerability_id: int
    plain_explanation: str
    remediation_summary: str
    secure_recommendation: str
    provenance: list[ProvenanceItem]


class FindingCluster(BaseModel):
    cluster_key: str
    count: int
    top_severity: str
    owasp_category: str
    cwe_ids: list[str]
    sample_vulnerability_ids: list[int]


class ScanExecutiveSummary(BaseModel):
    scan_id: int
    total_findings: int
    critical_findings: int
    high_findings: int
    open_findings: int
    summary_text: str
    clusters: list[FindingCluster]
