from config import Config
from detectors.anomaly_detector import AnomalyDetector
from detectors.prompt_detector import PromptDetector
from detectors.rate_detector import RateDetector
from detectors.secret_detector import SecretDetector
from detectors.token_detector import TokenDetector
from models.events import AIRequest, SecurityEvent, Severity

DETECTOR_MAP = {
    "rate": RateDetector,
    "secret": SecretDetector,
    "prompt": PromptDetector,
    "token": TokenDetector,
    "anomaly": AnomalyDetector,
}

SEVERITY_SCORES = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}


class DetectionEngine:
    def __init__(self):
        self._detectors = []
        for name in Config.ENABLED_DETECTORS:
            name = name.strip()
            if name in DETECTOR_MAP:
                self._detectors.append(DETECTOR_MAP[name]())

    def analyze(self, request: AIRequest) -> tuple[list[SecurityEvent], int]:
        events: list[SecurityEvent] = []
        for detector in self._detectors:
            event = detector.analyze(request)
            if event:
                events.append(event)

        risk_score = sum(SEVERITY_SCORES[e.severity] for e in events)
        return events, risk_score
