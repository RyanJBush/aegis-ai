import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.scanning import ScanRequest, ScanResponse
from app.services.audit_service import AuditService
from app.services.input_security import validate_scan_target
from app.services.scanner_engine import build_default_registry

logger = logging.getLogger(__name__)
DEFAULT_SCANNER = build_default_registry()


class ScanningService:
    @staticmethod
    def run_scan(db: Session, user_id: int, payload: ScanRequest) -> ScanResponse:
        clean_target = validate_scan_target(payload.target.strip().lower())
        scan = Scan(
            target=clean_target,
            payload=payload.payload,
            profile=payload.profile,
            baseline_scan_id=payload.baseline_scan_id,
            requested_by_user_id=user_id,
            status="queued",
        )
        db.add(scan)
        db.flush()
        AuditService.log(
            db,
            action="scan_queued",
            entity_type="scan",
            entity_id=scan.id,
            actor_user_id=user_id,
            details={"target": clean_target, "profile": payload.profile},
        )

        try:
            scan.status = "running"
            scan.started_at = datetime.now(UTC)
            AuditService.log(
                db,
                action="scan_started",
                entity_type="scan",
                entity_id=scan.id,
                actor_user_id=user_id,
            )

            findings: list[Vulnerability] = []
            seen_dedupe_keys: set[str] = set()
            suppression_keys = set(payload.suppression_keys)
            for finding in DEFAULT_SCANNER.run(payload.payload, payload.profile):
                if finding.dedupe_key in seen_dedupe_keys:
                    continue
                seen_dedupe_keys.add(finding.dedupe_key)
                is_suppressed = finding.dedupe_key in suppression_keys
                findings.append(
                    Vulnerability(
                        scan_id=scan.id,
                        rule_key=finding.rule_key,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        reason_code=finding.reason_code,
                        owasp_category=finding.owasp_category,
                        cwe_id=finding.cwe_id,
                        title=finding.title,
                        evidence=finding.evidence,
                        remediation=finding.remediation,
                        secure_example=finding.secure_example,
                        dedupe_key=finding.dedupe_key,
                        is_suppressed=is_suppressed,
                        status="false_positive" if is_suppressed else "open",
                    )
                )

            scan.status = "completed"
            scan.completed_at = datetime.now(UTC)
            if scan.started_at:
                scan.duration_ms = int((scan.completed_at - scan.started_at).total_seconds() * 1000)

            db.add_all(findings)
            AuditService.log(
                db,
                action="scan_completed",
                entity_type="scan",
                entity_id=scan.id,
                actor_user_id=user_id,
                details={
                    "total_findings": len(findings),
                    "suppressed_findings": sum(1 for f in findings if f.is_suppressed),
                },
            )
        except Exception as exc:
            scan.status = "failed"
            scan.completed_at = datetime.now(UTC)
            scan.failure_reason = str(exc)[:1000]
            if scan.started_at:
                scan.duration_ms = int((scan.completed_at - scan.started_at).total_seconds() * 1000)
            AuditService.log(
                db,
                action="scan_failed",
                entity_type="scan",
                entity_id=scan.id,
                actor_user_id=user_id,
                details={"failure_reason": scan.failure_reason},
            )
            db.commit()
            raise

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
            profile=scan.profile,
            status=scan.status,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            duration_ms=scan.duration_ms,
            failure_reason=scan.failure_reason,
            vulnerabilities_found=len(findings),
        )

    @staticmethod
    def mark_reviewed(db: Session, user_id: int, scan_id: int) -> Scan | None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.status = "reviewed"
        AuditService.log(
            db,
            action="scan_reviewed",
            entity_type="scan",
            entity_id=scan.id,
            actor_user_id=user_id,
        )
        db.commit()
        db.refresh(scan)
        return scan
