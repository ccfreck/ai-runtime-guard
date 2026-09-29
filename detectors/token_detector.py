from config import Config
from models.events import AIRequest, SecurityEvent, Severity


class TokenDetector:
    name = "token_detector"

    def __init__(self):
        self._threshold = Config.TOKEN_ANOMALY_THRESHOLD

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        if request.token_estimate <= self._threshold:
            return None

        return SecurityEvent(
            severity=Severity.MEDIUM,
            type="TOKEN_ANOMALY",
            user=request.user,
            model=request.model,
            detector=self.name,
            details={
                "source_ip": request.source_ip,
                "token_estimate": request.token_estimate,
                "threshold": self._threshold,
                "excess_ratio": round(request.token_estimate / self._threshold, 2),
            },
        )
