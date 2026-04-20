import logging
import re
from collections.abc import Iterable

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.scanning import ScanRequest, ScanResponse
from app.services.input_security import validate_scan_target

logger = logging.getLogger(__name__)

SQLI_PATTERNS = [
    re.compile(r"(?i)\bUNION\s+SELECT\b"),
    re.compile(r"(?i)(\bOR\b\s+\d+=\d+|\bOR\b\s+'\w+'='\w+')"),
    re.compile(r"(?i)--"),
]

XSS_PATTERNS = [
    re.compile(r"(?i)<script\b[^>]*>.*?</script>"),
    re.compile(r"(?i)onerror\s*=\s*['\"].*?['\"]"),
    re.compile(r"(?i)javascript:\s*"),
]


class ScanningService:
    @staticmethod
    def _extract_matches(payload: str, patterns: Iterable[re.Pattern[str]]) -> list[str]:
        matches: list[str] = []
        for pattern in patterns:
            matches.extend(match.group(0) for match in pattern.finditer(payload))
        return matches

    @staticmethod
    def run_scan(db: Session, user_id: int, payload: ScanRequest) -> ScanResponse:
        clean_target = validate_scan_target(payload.target.strip().lower())
        scan = Scan(target=clean_target, payload=payload.payload, requested_by_user_id=user_id, status="completed")
        db.add(scan)
        db.flush()

        findings: list[Vulnerability] = []
        sql_matches = ScanningService._extract_matches(payload.payload, SQLI_PATTERNS)
        xss_matches = ScanningService._extract_matches(payload.payload, XSS_PATTERNS)

        for evidence in sql_matches:
            normalized_evidence = evidence[:250]
            findings.append(
                Vulnerability(
                    scan_id=scan.id,
                    rule_key="SQLI",
                    severity="high",
                    title="Potential SQL Injection pattern",
                    evidence=normalized_evidence,
                    remediation="Use parameterized queries and strict input validation.",
                )
            )

        for evidence in xss_matches:
            normalized_evidence = evidence[:250]
            findings.append(
                Vulnerability(
                    scan_id=scan.id,
                    rule_key="XSS",
                    severity="medium",
                    title="Potential Cross-Site Scripting pattern",
                    evidence=normalized_evidence,
                    remediation="Contextually encode output and apply a strict CSP.",
                )
            )

        db.add_all(findings)
        db.commit()
        db.refresh(scan)

        logger.info(
            "Scan completed",
            extra={
                "scan_id": scan.id,
                "user_id": user_id,
                "target": clean_target,
                "findings": len(findings),
            },
        )

        return ScanResponse(
            id=scan.id,
            target=scan.target,
            status=scan.status,
            created_at=scan.created_at,
            vulnerabilities_found=len(findings),
        )
