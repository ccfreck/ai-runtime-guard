import time
from collections import defaultdict, deque

from config import Config
from models.events import AIRequest, SecurityEvent, Severity


class RateDetector:
    name = "rate_detector"

    def __init__(self):
        self._windows: dict[str, deque] = defaultdict(deque)
        self._threshold = Config.RATE_LIMIT_REQUESTS_PER_MINUTE

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        key = f"{request.user}:{request.source_ip}"
        now = time.time()
        window = self._windows[key]

        while window and now - window[0] > 60:
            window.popleft()

        window.append(now)

        if len(window) > self._threshold:
            return SecurityEvent(
                severity=Severity.MEDIUM,
                type="RATE_ANOMALY",
                user=request.user,
                model=request.model,
                detector=self.name,
                details={
                    "source_ip": request.source_ip,
                    "requests_in_window": len(window),
                    "threshold": self._threshold,
                    "window_seconds": 60,
                },
            )
        return None
