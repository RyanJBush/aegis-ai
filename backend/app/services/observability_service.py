from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.rule_change import RuleChangeEvent
from app.models.scan import Scan
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.observability import AuditLogRead, RuleChangeCreate, RuleChangeRead, ScanMetricsSummary
from app.services.audit_service import AuditService


class ObservabilityService:
    @staticmethod
    def list_audit_logs(
        db: Session,
        *,
        workspace_id: int,
        action: str | None = None,
        entity_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogRead]:
        workspace_user_ids = db.query(User.id).filter(User.workspace_id == workspace_id).subquery()
        query = db.query(AuditLog).filter(AuditLog.actor_user_id.in_(workspace_user_ids))
        if action:
            query = query.filter(AuditLog.action == action)
        if entity_type:
            query = query.filter(AuditLog.entity_type == entity_type)
        logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
        return [
            AuditLogRead(
                id=log.id,
                actor_user_id=log.actor_user_id,
                action=log.action,
                entity_type=log.entity_type,
                entity_id=log.entity_id,
                details=log.details,
                created_at=log.created_at,
            )
            for log in logs
        ]

    @staticmethod
    def get_scan_metrics(db: Session, *, workspace_id: int) -> ScanMetricsSummary:
        scans = db.query(Scan).filter(Scan.workspace_id == workspace_id).all()
        total_scans = len(scans)
        completed_scans = sum(1 for scan in scans if scan.status in {"completed", "reviewed"})
        failed_scans = sum(1 for scan in scans if scan.status == "failed")
        average_duration = (
            sum(float(scan.duration_ms or 0) for scan in scans) / total_scans if total_scans else 0.0
        )

        findings_counts = (
            db.query(Vulnerability.scan_id, func.count(Vulnerability.id))
            .filter(Vulnerability.workspace_id == workspace_id)
            .group_by(Vulnerability.scan_id)
            .all()
        )
        by_scan = {scan_id: count for scan_id, count in findings_counts}
        average_findings = (
            sum(by_scan.get(scan.id, 0) for scan in scans) / total_scans if total_scans else 0.0
        )

        success_rate = (float(completed_scans) / float(total_scans) * 100.0) if total_scans else 0.0
        return ScanMetricsSummary(
            total_scans=total_scans,
            completed_scans=completed_scans,
            failed_scans=failed_scans,
            success_rate_percent=round(success_rate, 2),
            average_duration_ms=round(float(average_duration), 2),
            average_findings_per_scan=round(float(average_findings), 2),
        )

    @staticmethod
    def create_rule_change(
        db: Session,
        *,
        workspace_id: int,
        actor_user_id: int,
        payload: RuleChangeCreate,
    ) -> RuleChangeRead:
        event = RuleChangeEvent(
            workspace_id=workspace_id,
            actor_user_id=actor_user_id,
            rule_key=payload.rule_key,
            change_type=payload.change_type,
            old_config=payload.old_config,
            new_config=payload.new_config,
            reason=payload.reason,
        )
        db.add(event)
        AuditService.log(
            db,
            action="scanner_rule_changed",
            entity_type="rule_change_event",
            actor_user_id=actor_user_id,
            details={"rule_key": payload.rule_key, "change_type": payload.change_type},
        )
        db.commit()
        db.refresh(event)
        return RuleChangeRead(
            id=event.id,
            workspace_id=event.workspace_id,
            actor_user_id=event.actor_user_id,
            rule_key=event.rule_key,
            change_type=event.change_type,
            old_config=event.old_config,
            new_config=event.new_config,
            reason=event.reason,
            created_at=event.created_at,
        )

    @staticmethod
    def list_rule_changes(db: Session, *, workspace_id: int, limit: int = 100, offset: int = 0) -> list[RuleChangeRead]:
        events = (
            db.query(RuleChangeEvent)
            .filter(RuleChangeEvent.workspace_id == workspace_id)
            .order_by(RuleChangeEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [
            RuleChangeRead(
                id=e.id,
                workspace_id=e.workspace_id,
                actor_user_id=e.actor_user_id,
                rule_key=e.rule_key,
                change_type=e.change_type,
                old_config=e.old_config,
                new_config=e.new_config,
                reason=e.reason,
                created_at=e.created_at,
            )
            for e in events
        ]
