"""
detectors/anomaly_detector.py — Statistical anomaly detection for user behavior.

Purpose:
    Builds a behavioral baseline for each user over time and flags requests
    that deviate significantly from their normal patterns. This catches
    subtle attacks that don't trigger any single rule but are unusual for
    the specific user.

Why this matters:
    Rule-based detectors catch known attack patterns. Anomaly detection
    catches the unknown — a user who suddenly starts using a different model,
    sending much larger prompts, or behaving differently than usual. This
    is often the first sign of account compromise.

How it works:
    Tracks two signals per user:
    1. Token usage history — uses z-score to detect statistical outliers
    2. Model usage — flags when a user accesses a model they've never used

    Z-score measures how many standard deviations a value is from the mean.
    A z-score > 3 means the value is in the top 0.15% of normal distribution.
"""

import statistics
from collections import defaultdict

from models.events import AIRequest, SecurityEvent, Severity


class AnomalyDetector:
    """
    Detects behavioral anomalies by comparing current requests against
    per-user historical baselines.

    This detector "learns" normal behavior over time, so it needs a few
    requests before it can make meaningful comparisons.
    """

    name = "anomaly_detector"

    def __init__(self):
        # Per-user history of token estimates (for z-score calculation)
        self._user_tokens: dict[str, list[int]] = defaultdict(list)

        # Per-user set of models they've used before
        self._user_models: dict[str, set[str]] = defaultdict(set)

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        """
        Compare this request against the user's established baseline.

        Returns:
            SecurityEvent if behavior is anomalous, None if it fits the baseline.
        """
        findings = {}

        # --- Check 1: New model usage ---
        # If the user has made requests before and this is a new model,
        # it could indicate account compromise or unauthorized exploration.
        if (
            request.user in self._user_models
            and request.model not in self._user_models[request.user]
        ):
            findings["new_model"] = request.model

        # Record this model in the user's history
        self._user_models[request.user].add(request.model)

        # --- Check 2: Token usage z-score ---
        # Need at least 5 data points for meaningful statistics
        token_history = self._user_tokens[request.user]
        if len(token_history) >= 5:
            mean = statistics.mean(token_history)
            # Standard deviation requires at least 2 data points
            stdev = statistics.stdev(token_history) if len(token_history) > 1 else 0

            # Only calculate z-score if there's variance in the data
            if stdev > 0:
                z_score = (request.token_estimate - mean) / stdev
                # Z-score > 3 means this is a 3-sigma event (very rare in normal distribution)
                if z_score > 3:
                    findings["token_z_score"] = round(z_score, 2)
                    findings["token_mean"] = round(mean, 2)
                    findings["token_stdev"] = round(stdev, 2)

        # Record this request's token count for future baseline calculations
        self._user_tokens[request.user].append(request.token_estimate)

        # If nothing unusual was found, return None
        if not findings:
            return None

        # Token z-score anomalies are more serious than new model usage
        severity = Severity.HIGH if "token_z_score" in findings else Severity.LOW

        return SecurityEvent(
            severity=severity,
            type="BEHAVIORAL_ANOMALY",
            user=request.user,
            model=request.model,
            detector=self.name,
            details={
                "source_ip": request.source_ip,
                "findings": findings,
            },
        )
