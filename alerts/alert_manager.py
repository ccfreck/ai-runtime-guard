import json
import logging
from datetime import datetime, timezone

import httpx

from config import Config
from models.events import SecurityEvent

logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self):
        self._webhook_url = Config.ALERT_WEBHOOK_URL

    def send_alert(self, event: SecurityEvent) -> None:
        self._log_to_console(event)
        self._send_to_webhook(event)

    def _log_to_console(self, event: SecurityEvent) -> None:
        logger.warning(
            f"[{event.severity.value}] {event.type} — "
            f"user={event.user} model={event.model} "
            f"detector={event.detector} details={event.details}"
        )

    def _send_to_webhook(self, event: SecurityEvent) -> None:
        if not self._webhook_url:
            return
        try:
            httpx.post(
                self._webhook_url,
                json=event.model_dump(mode="json"),
                timeout=5.0,
            )
        except httpx.HTTPError as e:
            logger.error(f"Failed to send alert to webhook: {e}")

    def to_cef(self, event: SecurityEvent) -> str:
        timestamp = event.timestamp.strftime("%b %d %Y %H:%M:%S")
        return (
            f"CEF:0|ai-runtime-guard|AI_API_MISUSE|1.0|{event.type}|{event.type}|"
            f"{self._severity_to_cef(event.severity.value)}|"
            f"src={event.source_ip} suser={event.user} cs1={event.model} "
            f"cs1Label=Model cs2={event.detector} cs2Label=Detector"
        )

    @staticmethod
    def _severity_to_cef(severity: str) -> int:
        mapping = {"LOW": 1, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
        return mapping.get(severity, 1)
