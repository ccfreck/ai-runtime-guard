"""
detectors/token_detector.py — Detects abnormal token consumption.

Purpose:
    Flags requests where the estimated token count is unusually high.
    This catches token abuse, denial-of-wallet attacks, and accidental
    large payloads that could result in unexpected API costs.

Why this matters:
    AI API costs scale with token usage. A single request with 100k+ tokens
    can cost more than thousands of normal requests. Attackers may exploit
    this by sending massive prompts to run up bills (denial-of-wallet).

How it works:
    Simple threshold-based detection. If the token estimate exceeds the
    configured threshold, the request is flagged. More sophisticated
    approaches (per-user baselines, time-series analysis) are handled by
    the anomaly detector.
"""

from config import Config
from models.events import AIRequest, SecurityEvent, Severity


class TokenDetector:
    """
    Flags requests with token estimates above a fixed threshold.

    This is a coarse but effective first line of defense against
    token-based abuse. It complements the anomaly detector which
    provides per-user behavioral analysis.
    """

    name = "token_detector"

    def __init__(self):
        # Load threshold from config (default: 10,000 tokens)
        self._threshold = Config.TOKEN_ANOMALY_THRESHOLD

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        """
        Check if this request's token estimate exceeds the threshold.

        Returns:
            SecurityEvent if token count is abnormally high, None otherwise.
        """
        # If token estimate is within normal range, no action needed
        if request.token_estimate <= self._threshold:
            return None

        # Token estimate exceeds threshold — flag it
        return SecurityEvent(
            severity=Severity.MEDIUM,  # Could be legitimate large context or abuse
            type="TOKEN_ANOMALY",
            user=request.user,
            model=request.model,
            detector=self.name,
            details={
                "source_ip": request.source_ip,
                "token_estimate": request.token_estimate,    # Actual token count
                "threshold": self._threshold,                # Configured limit
                "excess_ratio": round(request.token_estimate / self._threshold, 2),  # How many times over
            },
        )
