"""
alerts/alert_manager.py — Routes security events to alerting destinations.

Purpose:
    Takes detected security events and delivers them to the appropriate
    destinations: console logs, webhooks, and SIEM systems. This is the
    bridge between detection and response.

Why this matters:
    Detection without alerting is useless — someone needs to know when
    something bad happens. The alert manager ensures events reach the right
    people and systems quickly.

How it works:
    - Console logging: Always active, useful for development and debugging
    - Webhook: POSTs events to a configured URL (Slack, PagerDuty, custom)
    - CEF export: Formats events in Common Event Format for SIEM ingestion
      (Splunk, QRadar, ArcSight, etc.)
"""

import json
import logging
from datetime import datetime, timezone

import httpx

from config import Config
from models.events import SecurityEvent

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Delivers security events to configured alerting destinations.

    Designed to be extensible — new destinations (email, SMS, PagerDuty)
    can be added without changing the detection logic.
    """

    def __init__(self):
        # Webhook URL loaded from config. If empty, webhook alerts are skipped.
        self._webhook_url = Config.ALERT_WEBHOOK_URL

    def send_alert(self, event: SecurityEvent) -> None:
        """
        Send a security event to all configured destinations.

        This is the main entry point — call this for every detected event.
        """
        self._log_to_console(event)
        self._send_to_webhook(event)

    def _log_to_console(self, event: SecurityEvent) -> None:
        """
        Write the event to the application log.

        Always active regardless of configuration. Useful for local
        development and as a fallback when other destinations fail.
        """
        logger.warning(
            f"[{event.severity.value}] {event.type} — "
            f"user={event.user} model={event.model} "
            f"detector={event.detector} details={event.details}"
        )

    def _send_to_webhook(self, event: SecurityEvent) -> None:
        """
        POST the event as JSON to the configured webhook URL.

        Webhooks enable integration with Slack, Microsoft Teams,
        PagerDuty, or any HTTP endpoint. Failures are logged but
        don't crash the application — alerting should never block
        the detection pipeline.
        """
        if not self._webhook_url:
            return  # No webhook configured, skip silently

        try:
            httpx.post(
                self._webhook_url,
                json=event.model_dump(mode="json"),  # Serialize datetime to ISO format
                timeout=5.0,  # Don't wait forever — fail fast
            )
        except httpx.HTTPError as e:
            # Log the failure but don't raise — detection must continue
            logger.error(f"Failed to send alert to webhook: {e}")

    def to_cef(self, event: SecurityEvent) -> str:
        """
        Convert a security event to CEF (Common Event Format).

        CEF is a standard log format used by SIEM systems like Splunk,
        QRadar, and ArcSight. This method enables easy integration
        with enterprise security infrastructure.

        CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|
                    Signature ID|Name|Severity|Extension
        """
        timestamp = event.timestamp.strftime("%b %d %Y %H:%M:%S")
        return (
            f"CEF:0|ai-runtime-guard|AI_API_MISUSE|1.0|{event.type}|{event.type}|"
            f"{self._severity_to_cef(event.severity.value)}|"
            f"src={event.source_ip} suser={event.user} cs1={event.model} "
            f"cs1Label=Model cs2={event.detector} cs2Label=Detector"
        )

    @staticmethod
    def _severity_to_cef(severity: str) -> int:
        """
        Map internal severity levels to CEF numeric severity (1-10).

        CEF uses a 1-10 scale where 10 is most severe.
        """
        mapping = {"LOW": 1, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
        return mapping.get(severity, 1)  # Default to 1 for unknown severities
