from collections import defaultdict

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.ai import FindingAIInsight, FindingCluster, ProvenanceItem, ScanExecutiveSummary

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class AIAnalysisService:
    @staticmethod
    def generate_finding_insight(db: Session, workspace_id: int, vuln_id: int) -> FindingAIInsight | None:
        vuln = (
            db.query(Vulnerability)
            .filter(Vulnerability.workspace_id == workspace_id, Vulnerability.id == vuln_id)
            .first()
        )
        if not vuln:
            return None

        plain_explanation = (
            f"This finding indicates {vuln.title.lower()} with {vuln.severity} severity and "
            f"{round(vuln.confidence * 100)}% confidence."
        )
        remediation_summary = (
            f"Prioritize remediation for rule {vuln.rule_key}. {vuln.remediation} "
            f"Track status from {vuln.status} to fixed with owner assignment."
        )
        secure_recommendation = (
            f"Adopt secure-by-default controls for {vuln.owasp_category}, referencing {vuln.cwe_id}, "
            "and add automated tests that verify the vulnerable pattern is blocked."
        )

        provenance = [
            ProvenanceItem(kind="evidence", value=vuln.evidence[:200]),
            ProvenanceItem(kind="rule_key", value=vuln.rule_key),
            ProvenanceItem(kind="owasp", value=vuln.owasp_category),
            ProvenanceItem(kind="cwe", value=vuln.cwe_id),
        ]

        return FindingAIInsight(
            vulnerability_id=vuln.id,
            plain_explanation=plain_explanation,
            remediation_summary=remediation_summary,
            secure_recommendation=secure_recommendation,
            provenance=provenance,
        )

    @staticmethod
    def generate_scan_executive_summary(db: Session, workspace_id: int, scan_id: int) -> ScanExecutiveSummary | None:
        scan = db.query(Scan).filter(Scan.workspace_id == workspace_id, Scan.id == scan_id).first()
        if not scan:
            return None
        findings = (
            db.query(Vulnerability)
            .filter(Vulnerability.workspace_id == workspace_id, Vulnerability.scan_id == scan_id)
            .all()
        )

        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        open_count = sum(1 for f in findings if f.status in {"open", "triaged"})

        grouped: dict[tuple[str, str], list[Vulnerability]] = defaultdict(list)
        for finding in findings:
            grouped[(finding.owasp_category, finding.rule_key)].append(finding)

        clusters: list[FindingCluster] = []
        for (owasp, rule_key), cluster_findings in grouped.items():
            top = max(cluster_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity
            cwe_ids = sorted({f.cwe_id for f in cluster_findings})
            sample_ids = [f.id for f in cluster_findings[:5]]
            clusters.append(
                FindingCluster(
                    cluster_key=rule_key,
                    count=len(cluster_findings),
                    top_severity=top,
                    owasp_category=owasp,
                    cwe_ids=cwe_ids,
                    sample_vulnerability_ids=sample_ids,
                )
            )

        clusters.sort(key=lambda c: (SEVERITY_ORDER.get(c.top_severity, 0), c.count), reverse=True)
        summary_text = (
            f"Scan {scan_id} identified {total} findings ({critical} critical / {high} high). "
            f"{open_count} findings remain open or triaged across {len(clusters)} clusters."
        )

        return ScanExecutiveSummary(
            scan_id=scan_id,
            total_findings=total,
            critical_findings=critical,
            high_findings=high,
            open_findings=open_count,
            summary_text=summary_text,
            clusters=clusters,
        )
