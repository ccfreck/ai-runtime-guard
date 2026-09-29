"""
detectors/rate_detector.py — Detects abnormal request frequency (rate abuse).

Purpose:
    Tracks how many requests each user sends per minute and flags when
    someone exceeds a reasonable threshold. This catches automated scraping,
    runaway scripts, credential stuffing, or denial-of-wallet attacks.

Why this matters:
    AI APIs are expensive. A compromised account or buggy integration can
    fire thousands of requests per minute, racking up massive costs or
    degrading service for everyone else.

How it works:
    Uses a sliding window approach: for each user+IP combination, it keeps
    a queue of timestamps from the last 60 seconds. If the queue exceeds
    the threshold, the request is flagged. Old timestamps are pruned on
    each check so memory usage stays bounded.
"""

import time
from collections import defaultdict, deque

from config import Config
from models.events import AIRequest, SecurityEvent, Severity


class RateDetector:
    """
    Monitors request rate per user/IP using a sliding 60-second window.

    The sliding window is more accurate than a fixed window because it
    won't miss bursts that span window boundaries.
    """

    name = "rate_detector"

    def __init__(self):
        # Maps "user:ip" -> deque of request timestamps (seconds since epoch)
        # Using deque for O(1) append and popleft operations
        self._windows: dict[str, deque] = defaultdict(deque)

        # Load the threshold from config (default: 60 requests/minute)
        self._threshold = Config.RATE_LIMIT_REQUESTS_PER_MINUTE

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        """
        Check if this user+IP has exceeded the rate limit.

        Returns:
            SecurityEvent if rate limit exceeded, None otherwise.
        """
        # Create a unique key per user+IP pair
        # This prevents one user from bypassing limits by switching IPs
        key = f"{request.user}:{request.source_ip}"
        now = time.time()
        window = self._windows[key]

        # Remove timestamps older than 60 seconds (sliding window)
        # This keeps only requests from the last minute in the queue
        while window and now - window[0] > 60:
            window.popleft()

        # Add current request timestamp
        window.append(now)

        # Check if we've exceeded the threshold
        if len(window) > self._threshold:
            return SecurityEvent(
                severity=Severity.MEDIUM,  # Rate abuse is MEDIUM — could be a bug or attack
                type="RATE_ANOMALY",
                user=request.user,
                model=request.model,
                detector=self.name,
                details={
                    "source_ip": request.source_ip,
                    "requests_in_window": len(window),  # How many in the last 60s
                    "threshold": self._threshold,        # What the limit is
                    "window_seconds": 60,               # Window size
                },
            )
        return None
