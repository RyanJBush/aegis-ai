from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.user import Role, User
from app.models.vulnerability import Vulnerability
from app.models.workspace import Workspace
from app.schemas.observability import RuleChangeCreate
from app.services.ai_analysis_service import AIAnalysisService
from app.services.alert_service import AlertService
from app.services.input_security import validate_scan_target
from app.services.observability_service import ObservabilityService


def _create_workspace_user(db: Session, *, suffix: str = "1") -> tuple[Workspace, User]:
    workspace = Workspace(name=f"workspace-{suffix}", slug=f"workspace-{suffix}")
    db.add(workspace)
    db.flush()
    user = User(
        workspace_id=workspace.id,
        email=f"user-{suffix}@example.com",
        hashed_password="hashed",
        role=Role.security_analyst,
    )
    db.add(user)
    db.flush()
    return workspace, user


def _create_scan(db: Session, *, workspace_id: int, user_id: int, status: str = "completed", duration_ms: int = 100) -> Scan:
    scan = Scan(
        workspace_id=workspace_id,
        target="https://service.example.com",
        payload="payload",
        requested_by_user_id=user_id,
        status=status,
        profile="standard",
        started_at=datetime.now(UTC) - timedelta(seconds=2),
        completed_at=datetime.now(UTC),
        duration_ms=duration_ms,
    )
    db.add(scan)
    db.flush()
    return scan


def _create_vulnerability(
    db: Session,
    *,
    workspace_id: int,
    scan_id: int,
    rule_key: str,
    severity: str = "medium",
    status: str = "open",
    dedupe_suffix: str = "1",
) -> Vulnerability:
    vuln = Vulnerability(
        workspace_id=workspace_id,
        scan_id=scan_id,
        rule_key=rule_key,
        severity=severity,
        confidence=0.91,
        reason_code="TEST_REASON",
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-79",
        title="Cross-Site Scripting",
        evidence="X" * 300,
        remediation="Escape untrusted output",
        secure_example="<div>{escaped}</div>",
        dedupe_key=f"{rule_key}-{dedupe_suffix}",
        status=status,
    )
    db.add(vuln)
    db.flush()
    return vuln


def test_ai_generate_finding_insight_and_missing_vulnerability(db_session: Session) -> None:
    workspace, user = _create_workspace_user(db_session, suffix="ai-1")
    scan = _create_scan(db_session, workspace_id=workspace.id, user_id=user.id)
    vuln = _create_vulnerability(
        db_session,
        workspace_id=workspace.id,
        scan_id=scan.id,
        rule_key="XSS_INJECTION",
        severity="high",
    )
    db_session.commit()

    insight = AIAnalysisService.generate_finding_insight(
        db_session,
        workspace_id=workspace.id,
        vuln_id=vuln.id,
    )
    assert insight is not None
    assert insight.vulnerability_id == vuln.id
    assert "cross-site scripting" in insight.plain_explanation
    assert "XSS_INJECTION" in insight.remediation_summary
    assert len(insight.provenance) == 4
    assert insight.provenance[0].kind == "evidence"
    assert len(insight.provenance[0].value) == 200

    assert AIAnalysisService.generate_finding_insight(db_session, workspace_id=workspace.id, vuln_id=99999) is None


def test_ai_generate_scan_executive_summary_clusters_and_sorting(db_session: Session) -> None:
    workspace, user = _create_workspace_user(db_session, suffix="ai-2")
    scan = _create_scan(db_session, workspace_id=workspace.id, user_id=user.id, duration_ms=250)

    for i in range(6):
        _create_vulnerability(
            db_session,
            workspace_id=workspace.id,
            scan_id=scan.id,
            rule_key="SQLI",
            severity="critical" if i == 0 else "high",
            status="triaged" if i % 2 else "open",
            dedupe_suffix=f"sqli-{i}",
        )
    _create_vulnerability(
        db_session,
        workspace_id=workspace.id,
        scan_id=scan.id,
        rule_key="INFO_RULE",
        severity="low",
        status="closed",
        dedupe_suffix="info",
    )
    db_session.commit()

    summary = AIAnalysisService.generate_scan_executive_summary(
        db_session,
        workspace_id=workspace.id,
        scan_id=scan.id,
    )
    assert summary is not None
    assert summary.total_findings == 7
    assert summary.critical_findings == 1
    assert summary.high_findings == 5
    assert summary.open_findings == 6
    assert summary.clusters[0].cluster_key == "SQLI"
    assert summary.clusters[0].top_severity == "critical"
    assert len(summary.clusters[0].sample_vulnerability_ids) == 5
    assert "identified 7 findings" in summary.summary_text

    assert AIAnalysisService.generate_scan_executive_summary(db_session, workspace_id=workspace.id, scan_id=99999) is None


def test_observability_list_audit_logs_filters_workspace_and_pagination(db_session: Session) -> None:
    workspace_1, user_1 = _create_workspace_user(db_session, suffix="obs-1")
    workspace_2, user_2 = _create_workspace_user(db_session, suffix="obs-2")

    now = datetime.now(UTC)
    db_session.add_all(
        [
            AuditLog(
                actor_user_id=user_1.id,
                action="scan_started",
                entity_type="scan",
                details={"idx": 1},
                created_at=now - timedelta(minutes=2),
            ),
            AuditLog(
                actor_user_id=user_1.id,
                action="scan_completed",
                entity_type="scan",
                details={"idx": 2},
                created_at=now - timedelta(minutes=1),
            ),
            AuditLog(
                actor_user_id=user_2.id,
                action="scanner_rule_changed",
                entity_type="rule_change_event",
                details={"idx": 3},
                created_at=now,
            ),
        ]
    )
    db_session.commit()

    workspace_logs = ObservabilityService.list_audit_logs(db_session, workspace_id=workspace_1.id)
    assert len(workspace_logs) == 2
    assert all(log.actor_user_id == user_1.id for log in workspace_logs)
    assert workspace_logs[0].action == "scan_completed"

    filtered = ObservabilityService.list_audit_logs(
        db_session,
        workspace_id=workspace_1.id,
        action="scan_started",
        entity_type="scan",
    )
    assert len(filtered) == 1
    assert filtered[0].action == "scan_started"

    paged = ObservabilityService.list_audit_logs(db_session, workspace_id=workspace_1.id, limit=1, offset=1)
    assert len(paged) == 1
    assert paged[0].action == "scan_started"
    assert workspace_2.id != workspace_1.id


def test_observability_metrics_and_rule_changes(db_session: Session) -> None:
    workspace, user = _create_workspace_user(db_session, suffix="obs-3")

    scan_completed = _create_scan(
        db_session,
        workspace_id=workspace.id,
        user_id=user.id,
        status="completed",
        duration_ms=120,
    )
    scan_reviewed = _create_scan(
        db_session,
        workspace_id=workspace.id,
        user_id=user.id,
        status="reviewed",
        duration_ms=180,
    )
    _create_scan(
        db_session,
        workspace_id=workspace.id,
        user_id=user.id,
        status="failed",
        duration_ms=0,
    )

    _create_vulnerability(
        db_session,
        workspace_id=workspace.id,
        scan_id=scan_completed.id,
        rule_key="RULE1",
        severity="high",
        dedupe_suffix="m-1",
    )
    _create_vulnerability(
        db_session,
        workspace_id=workspace.id,
        scan_id=scan_completed.id,
        rule_key="RULE2",
        severity="medium",
        dedupe_suffix="m-2",
    )
    _create_vulnerability(
        db_session,
        workspace_id=workspace.id,
        scan_id=scan_reviewed.id,
        rule_key="RULE3",
        severity="low",
        dedupe_suffix="m-3",
    )
    db_session.commit()

    metrics = ObservabilityService.get_scan_metrics(db_session, workspace_id=workspace.id)
    assert metrics.total_scans == 3
    assert metrics.completed_scans == 2
    assert metrics.failed_scans == 1
    assert metrics.success_rate_percent == pytest.approx(66.67, abs=0.01)
    assert metrics.average_duration_ms == pytest.approx((120 + 180 + 0) / 3, abs=0.01)
    assert metrics.average_findings_per_scan == pytest.approx(3 / 3, abs=0.01)

    rule_change = ObservabilityService.create_rule_change(
        db_session,
        workspace_id=workspace.id,
        actor_user_id=user.id,
        payload=RuleChangeCreate(
            rule_key="SECRET_DETECTION",
            change_type="threshold_update",
            old_config={"min_confidence": 0.8},
            new_config={"min_confidence": 0.9},
            reason="Reduce false positives",
        ),
    )
    assert rule_change.rule_key == "SECRET_DETECTION"
    assert rule_change.workspace_id == workspace.id

    audit_entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "scanner_rule_changed", AuditLog.actor_user_id == user.id)
        .first()
    )
    assert audit_entry is not None
    assert audit_entry.details["rule_key"] == "SECRET_DETECTION"

    listed = ObservabilityService.list_rule_changes(db_session, workspace_id=workspace.id)
    assert len(listed) == 1
    assert listed[0].id == rule_change.id


def test_alert_service_notifies_webhook_and_handles_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _MockResponse:
        def __init__(self, status: int) -> None:
            self.status = status

        def __enter__(self) -> "_MockResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    monkeypatch.setattr(settings, "alert_webhook_url", None)
    with patch("app.services.alert_service.request.urlopen") as urlopen_mock:
        AlertService.notify_critical_findings(scan_id=1, target="https://target", critical_count=2)
        assert not urlopen_mock.called

    monkeypatch.setattr(settings, "alert_webhook_url", "https://alerts.example.com/webhook")
    with patch("app.services.alert_service.request.urlopen") as urlopen_mock:
        AlertService.notify_critical_findings(scan_id=1, target="https://target", critical_count=0)
        assert not urlopen_mock.called

    with patch("app.services.alert_service.request.urlopen", return_value=_MockResponse(202)) as urlopen_mock:
        AlertService.notify_critical_findings(scan_id=42, target="https://target", critical_count=3)
        assert urlopen_mock.called
        req = urlopen_mock.call_args.args[0]
        assert req.full_url == settings.alert_webhook_url
        assert req.method == "POST"

    with (
        patch("app.services.alert_service.request.urlopen", return_value=_MockResponse(500)),
        patch("app.services.alert_service.logger.warning") as logger_warning,
    ):
        AlertService.notify_critical_findings(scan_id=43, target="https://target", critical_count=4)
        logger_warning.assert_called_once()

    with (
        patch("app.services.alert_service.request.urlopen", side_effect=RuntimeError("network down")),
        patch("app.services.alert_service.logger.exception") as logger_exception,
    ):
        AlertService.notify_critical_findings(scan_id=7, target="https://target", critical_count=1)
        logger_exception.assert_called_once()


@pytest.mark.parametrize(
    ("target", "expected_detail"),
    [
        ("ftp://example.com", "Target must be HTTP/HTTPS URL"),
        ("https://", "Target hostname is required"),
        ("http://localhost/login", "Localhost targets are not allowed"),
        ("http://10.0.0.1/api", "Private IP targets are not allowed"),
    ],
)
def test_validate_scan_target_rejects_invalid_targets(target: str, expected_detail: str) -> None:
    with pytest.raises(HTTPException) as exc:
        validate_scan_target(target)
    assert exc.value.status_code == 400
    assert exc.value.detail == expected_detail


def test_validate_scan_target_accepts_public_url() -> None:
    target = "https://example.org/path?q=1"
    assert validate_scan_target(target) == target
