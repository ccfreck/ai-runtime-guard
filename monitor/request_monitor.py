"""
monitor/request_monitor.py — Intercepts and normalizes incoming AI API requests.

Purpose:
    Acts as the entry point between raw application traffic and the detection
    engine. It normalizes various request formats into the standard AIRequest
    model, logs all requests for audit purposes, and tracks basic metrics
    (total requests, blocked count, etc.).

Why this matters:
    In production, requests come from many sources (web apps, mobile, internal
    services) with slightly different formats. The request monitor ensures
    they all get normalized before inspection, so detectors don't need to
    handle format variations.

How it works:
    1. Accepts raw request data (dict or AIRequest)
    2. Normalizes it into a standard AIRequest
    3. Logs the request for audit trail
    4. Tracks metrics (total, allowed, blocked)
    5. Passes it to the detection engine
    6. Returns the inspection result
"""

import logging
from datetime import datetime, timezone

from models.events import AIRequest, SecurityEvent
from monitor.detection_engine import DetectionEngine

logger = logging.getLogger(__name__)


class RequestMonitor:
    """
    Intercepts, normalizes, and logs all incoming AI API requests.

    This is the single entry point that all traffic flows through.
    It ensures every request is properly formatted before detection
    and maintains an audit trail of all activity.
    """

    def __init__(self, engine: DetectionEngine):
        """
        Initialize the request monitor with a detection engine.

        Args:
            engine: The DetectionEngine instance to use for inspection.
        """
        self._engine = engine

        # Simple in-memory metrics for monitoring and dashboards
        self._metrics = {
            "total_requests": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "start_time": datetime.now(timezone.utc),
        }

    def process(self, raw_request: dict | AIRequest) -> tuple[list[SecurityEvent], int, bool]:
        """
        Process a raw request through the full inspection pipeline.

        Args:
            raw_request: Either an AIRequest object or a dict with request data.

        Returns:
            A tuple of (events, risk_score, allowed)
            - events: List of security events detected
            - risk_score: Aggregate risk score
            - allowed: True if the request should be allowed through
        """
        # Step 1: Normalize the request into standard format
        request = self._normalize(raw_request)

        # Step 2: Log for audit trail
        self._log_request(request)

        # Step 3: Run detection
        events, risk_score = self._engine.analyze(request)

        # Step 4: Determine if request should be allowed
        allowed = risk_score < 10

        # Step 5: Update metrics
        self._update_metrics(allowed)

        return events, risk_score, allowed

    def _normalize(self, raw_request: dict | AIRequest) -> AIRequest:
        """
        Convert raw request data into a standard AIRequest model.

        Handles missing fields by applying sensible defaults, so detectors
        can always rely on a complete, valid request object.
        """
        if isinstance(raw_request, AIRequest):
            return raw_request

        # Build AIRequest from dict, using defaults for missing fields
        return AIRequest(
            user=raw_request.get("user", "unknown"),
            model=raw_request.get("model", "unknown"),
            prompt=raw_request.get("prompt", ""),
            source_ip=raw_request.get("source_ip", "unknown"),
            token_estimate=raw_request.get("token_estimate", 0),
        )

    def _log_request(self, request: AIRequest) -> None:
        """
        Log the request for audit purposes.

        In production, this would write to a structured log or SIEM.
        For now, it logs at DEBUG level to avoid noise.
        """
        logger.debug(
            f"Request: user={request.user} model={request.model} "
            f"ip={request.source_ip} tokens={request.token_estimate}"
        )

    def _update_metrics(self, allowed: bool) -> None:
        """Update internal counters for monitoring and dashboards."""
        self._metrics["total_requests"] += 1
        if allowed:
            self._metrics["allowed_requests"] += 1
        else:
            self._metrics["blocked_requests"] += 1

    def get_metrics(self) -> dict:
        """
        Return current metrics snapshot.

        Used by dashboards and monitoring endpoints to show
        system activity and detection rates.
        """
        return {
            **self._metrics,
            "uptime_seconds": (
                datetime.now(timezone.utc) - self._metrics["start_time"]
            ).total_seconds(),
        }
