import json
import logging
from urllib import request

from app.core.config import settings

logger = logging.getLogger(__name__)


class AlertService:
    @staticmethod
    def notify_critical_findings(*, scan_id: int, target: str, critical_count: int) -> None:
        if critical_count <= 0 or not settings.alert_webhook_url:
            return

        payload = {
            "event": "critical_findings_detected",
            "scan_id": scan_id,
            "target": target,
            "critical_count": critical_count,
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            settings.alert_webhook_url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=3) as response:  # noqa: S310
                if response.status >= 400:
                    logger.warning("Alert webhook returned non-success status", extra={"status": response.status})
        except Exception:
            logger.exception("Failed to deliver alert webhook")
