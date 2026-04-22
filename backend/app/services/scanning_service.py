import logging
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.vulnerability import Vulnerability
from app.schemas.scanning import (
    CIGateReport,
    PolicyGateRequest,
    SarifReport,
    ScanDiffSummary,
    ScanJobRead,
    ScanReportBundle,
    ScanRequest,
    ScanResponse,
    ScanTrendPoint,
    ScanTrendResponse,
    SuppressionExport,
    RemediationChecklistResponse,
    DevSecOpsSnippetScanRequest,
)
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService
from app.services.input_security import validate_scan_target
from app.services.scanner_engine import build_default_registry

logger = logging.getLogger(__name__)
DEFAULT_SCANNER = build_default_registry()
MAX_FAILURE_REASON_LENGTH = 1000
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class ScanningService:
    @staticmethod
    def enqueue_scan(db: Session, user_id: int, workspace_id: int, payload: ScanRequest) -> ScanJobRead:
        job = ScanJob(requested_by_user_id=user_id, status="queued")
        db.add(job)
        db.flush()
        AuditService.log(
            db,
            action="scan_job_queued",
            entity_type="scan_job",
            entity_id=job.id,
            actor_user_id=user_id,
            details={"target": payload.target, "profile": payload.profile, "workspace_id": workspace_id},
        )
        db.commit()
        db.refresh(job)
        return ScanJobRead.model_validate(job)

    @staticmethod
    def process_queued_job(job_id: int, user_id: int, workspace_id: int, payload: ScanRequest) -> None:
        db = SessionLocal()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if not job:
                return
            job.status = "running"
            job.started_at = datetime.now(UTC)
            db.commit()
            result = ScanningService.run_scan(db=db, user_id=user_id, workspace_id=workspace_id, payload=payload)

            job.scan_id = result.id
            job.status = "completed"
            job.completed_at = datetime.now(UTC)
            db.commit()
        except Exception as exc:
            if job:
                job.status = "failed"
                job.failure_reason = str(exc)[:MAX_FAILURE_REASON_LENGTH]
                job.completed_at = datetime.now(UTC)
                AuditService.log(
                    db,
                    action="scan_job_failed",
                    entity_type="scan_job",
                    entity_id=job.id,
                    actor_user_id=user_id,
                    details={"failure_reason": job.failure_reason},
                )
                db.commit()
            logger.exception("Queued scan job failed", extra={"job_id": job_id})
        finally:
            db.close()

    @staticmethod
    def run_scan(db: Session, user_id: int, workspace_id: int, payload: ScanRequest) -> ScanResponse:
        clean_target = validate_scan_target(payload.target.strip().lower())
        scan = Scan(
            target=clean_target,
            payload=payload.payload,
            profile=payload.profile,
            baseline_scan_id=payload.baseline_scan_id,
            requested_by_user_id=user_id,
            workspace_id=workspace_id,
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
            details={"target": clean_target, "profile": payload.profile, "baseline_scan_id": payload.baseline_scan_id, "workspace_id": workspace_id},
        )

        diff_summary = ScanDiffSummary(baseline_scan_id=payload.baseline_scan_id)
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
                        workspace_id=workspace_id,
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

            diff_summary = ScanningService.build_diff_summary(
                db=db,
                baseline_scan_id=payload.baseline_scan_id,
                current_dedupe_keys=seen_dedupe_keys,
            )

            scan.status = "completed"
            scan.completed_at = datetime.now(UTC)
            if scan.started_at:
                scan.duration_ms = int((scan.completed_at - scan.started_at).total_seconds() * 1000)

            db.add_all(findings)
            critical_count = sum(1 for finding in findings if finding.severity == "critical" and not finding.is_suppressed)
            AlertService.notify_critical_findings(scan_id=scan.id, target=scan.target, critical_count=critical_count)
            AuditService.log(
                db,
                action="scan_completed",
                entity_type="scan",
                entity_id=scan.id,
                actor_user_id=user_id,
                details={
                    "total_findings": len(findings),
                    "suppressed_findings": sum(1 for f in findings if f.is_suppressed),
                    "critical_findings": critical_count,
                    "new_findings": diff_summary.new_findings,
                    "resolved_findings": diff_summary.resolved_findings,
                },
            )
        except Exception as exc:
            scan.status = "failed"
            scan.completed_at = datetime.now(UTC)
            scan.failure_reason = str(exc)[:MAX_FAILURE_REASON_LENGTH]
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
            extra={"scan_id": scan.id, "user_id": user_id, "target": clean_target, "findings": len(findings)},
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
            diff_summary=diff_summary,
        )

    @staticmethod
    def mark_reviewed(db: Session, user_id: int, workspace_id: int, scan_id: int) -> Scan | None:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.workspace_id == workspace_id).first()
        if not scan:
            return None
        scan.status = "reviewed"
        AuditService.log(db, action="scan_reviewed", entity_type="scan", entity_id=scan.id, actor_user_id=user_id)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def build_diff_summary(db: Session, baseline_scan_id: int | None, current_dedupe_keys: set[str]) -> ScanDiffSummary:
        if baseline_scan_id is None:
            return ScanDiffSummary()
        baseline_rows = db.query(Vulnerability.dedupe_key).filter(Vulnerability.scan_id == baseline_scan_id).all()
        baseline_dedupe_keys = {row[0] for row in baseline_rows}
        return ScanDiffSummary(
            baseline_scan_id=baseline_scan_id,
            new_findings=len(current_dedupe_keys - baseline_dedupe_keys),
            repeated_findings=len(current_dedupe_keys & baseline_dedupe_keys),
            resolved_findings=len(baseline_dedupe_keys - current_dedupe_keys),
        )

    @staticmethod
    def build_policy_gate_report(db: Session, workspace_id: int, scan_id: int, payload: PolicyGateRequest) -> CIGateReport | None:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.workspace_id == workspace_id).first()
        if not scan:
            return None
        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id, Vulnerability.workspace_id == workspace_id, Vulnerability.is_suppressed.is_(False)).all()
        threshold = SEVERITY_ORDER[payload.max_allowed_severity]
        blocking_findings = [
            v
            for v in findings
            if SEVERITY_ORDER.get(v.severity, 0) > threshold and (not payload.fail_on_open or v.status in {"open", "triaged"})
        ]
        return CIGateReport(
            scan_id=scan_id,
            passed=len(blocking_findings) == 0,
            blocking_findings=len(blocking_findings),
            summary=CounterLike.count_severity(findings),
        )

    @staticmethod
    def export_suppressions(db: Session, workspace_id: int, scan_id: int) -> SuppressionExport | None:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.workspace_id == workspace_id).first()
        if not scan:
            return None
        suppressed = db.query(Vulnerability.dedupe_key).filter(
            Vulnerability.scan_id == scan_id,
            Vulnerability.workspace_id == workspace_id,
            Vulnerability.status == "false_positive",
        )
        return SuppressionExport(scan_id=scan_id, suppression_keys=[row[0] for row in suppressed.all()])

    @staticmethod
    def build_scan_trends(db: Session, workspace_id: int, days: int = 14) -> ScanTrendResponse:
        scans = db.query(Scan).filter(Scan.workspace_id == workspace_id).order_by(Scan.created_at.desc()).limit(days * 20).all()
        bucket: dict[str, dict[str, float]] = {}
        for scan in scans:
            day = scan.created_at.date().isoformat()
            bucket.setdefault(day, {"scans": 0.0, "findings": 0.0, "duration_sum": 0.0, "duration_count": 0.0})
            bucket[day]["scans"] += 1
            bucket[day]["duration_sum"] += float(scan.duration_ms or 0)
            bucket[day]["duration_count"] += 1

        finding_rows = (
            db.query(func.date(Scan.created_at), func.count(Vulnerability.id))
            .join(Vulnerability, Vulnerability.scan_id == Scan.id)
            .filter(Scan.workspace_id == workspace_id, Vulnerability.workspace_id == workspace_id)
            .group_by(func.date(Scan.created_at))
            .all()
        )
        for day, finding_count in finding_rows:
            iso_day = day.isoformat()
            bucket.setdefault(iso_day, {"scans": 0.0, "findings": 0.0, "duration_sum": 0.0, "duration_count": 0.0})
            bucket[iso_day]["findings"] = float(finding_count)

        ordered_days = sorted(bucket.keys())[-days:]
        points = [
            ScanTrendPoint(
                day=datetime.fromisoformat(day).date(),
                scans=int(bucket[day]["scans"]),
                findings=int(bucket[day]["findings"]),
                avg_duration_ms=round(bucket[day]["duration_sum"] / max(bucket[day]["duration_count"], 1.0), 2),
            )
            for day in ordered_days
        ]
        return ScanTrendResponse(points=points)

    @staticmethod
    def build_report_bundle(db: Session, workspace_id: int, scan_id: int) -> ScanReportBundle | None:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.workspace_id == workspace_id).first()
        if not scan:
            return None
        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id, Vulnerability.workspace_id == workspace_id).all()
        return ScanReportBundle(
            scan_id=scan_id,
            generated_at=datetime.now(UTC),
            findings=[
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "owasp": finding.owasp_category,
                    "cwe": finding.cwe_id,
                    "dedupe_key": finding.dedupe_key,
                }
                for finding in findings
            ],
        )

    @staticmethod
    def build_sarif_report(db: Session, workspace_id: int, scan_id: int) -> SarifReport | None:
        bundle = ScanningService.build_report_bundle(db=db, workspace_id=workspace_id, scan_id=scan_id)
        if not bundle:
            return None
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "Aegis AI Scanner", "version": "0.4.0"}},
                    "results": [
                        {
                            "ruleId": finding["dedupe_key"],
                            "level": finding["severity"],
                            "message": {"text": finding["title"]},
                        }
                        for finding in bundle.findings
                    ],
                }
            ],
        }
        return SarifReport(scan_id=scan_id, sarif=sarif)

    @staticmethod
    def run_snippet_scan(
        db: Session,
        *,
        user_id: int,
        workspace_id: int,
        payload: DevSecOpsSnippetScanRequest,
    ) -> ScanResponse:
        normalized_target = f"{payload.target.strip()}#{payload.snippet_type}"
        mapped = ScanRequest(
            target=normalized_target,
            payload=payload.snippet,
            profile=payload.profile,
            baseline_scan_id=payload.baseline_scan_id,
            suppression_keys=payload.suppression_keys,
        )
        return ScanningService.run_scan(db=db, user_id=user_id, workspace_id=workspace_id, payload=mapped)

    @staticmethod
    def build_remediation_checklist(db: Session, *, workspace_id: int, scan_id: int) -> RemediationChecklistResponse | None:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.workspace_id == workspace_id).first()
        if not scan:
            return None
        findings = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan_id, Vulnerability.workspace_id == workspace_id)
            .all()
        )
        tasks: list[str] = []
        for finding in findings:
            tasks.append(f"[{finding.severity.upper()}] Fix {finding.rule_key}: {finding.remediation}")
            if finding.owasp_category.startswith("A05"):
                tasks.append("Review deployment/config baselines and enforce policy checks in CI")
            if finding.rule_key in {"SECRET_DETECTION", "SENSITIVE_DATA_EXPOSURE"}:
                tasks.append("Rotate exposed credentials and validate secret scanning coverage")
        # de-duplicate while preserving order
        deduped = list(dict.fromkeys(tasks))
        return RemediationChecklistResponse(scan_id=scan_id, checklist=deduped)


class CounterLike:
    @staticmethod
    def count_severity(findings: list[Vulnerability]) -> dict[str, int]:
        summary: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for finding in findings:
            if finding.severity in summary:
                summary[finding.severity] += 1
        return summary
