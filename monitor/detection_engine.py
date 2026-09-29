"""
monitor/detection_engine.py — Orchestrates all detectors and aggregates results.

Purpose:
    This is the brain of the system. It initializes all enabled detectors,
    runs them against each incoming request, and combines their results into
    a unified risk assessment.

Why this matters:
    Individual detectors each look for one type of misuse. The detection
    engine combines them so a single request can trigger multiple alerts
    (e.g., a prompt with secrets AND injection attempts). The combined risk
    score gives a single number that can be used for automated blocking.

How it works:
    1. On startup, reads the enabled detector list from config
    2. For each request, runs all detectors in sequence
    3. Collects all security events produced
    4. Calculates a total risk score by summing severity weights
    5. Returns both the individual events and the aggregate score
"""

from config import Config
from detectors.anomaly_detector import AnomalyDetector
from detectors.prompt_detector import PromptDetector
from detectors.rate_detector import RateDetector
from detectors.secret_detector import SecretDetector
from detectors.token_detector import TokenDetector
from models.events import AIRequest, SecurityEvent, Severity

# Maps detector names (from config) to their implementation classes.
# Adding a new detector only requires adding an entry here.
DETECTOR_MAP = {
    "rate": RateDetector,
    "secret": SecretDetector,
    "prompt": PromptDetector,
    "token": TokenDetector,
    "anomaly": AnomalyDetector,
}

# Numeric weights for each severity level.
# These determine how much each detector's finding contributes to the
# overall risk score. Higher = more dangerous.
SEVERITY_SCORES = {
    Severity.LOW: 1,       # Minor issue
    Severity.MEDIUM: 3,    # Worth investigating
    Severity.HIGH: 6,      # Likely malicious
    Severity.CRITICAL: 10, # Confirmed attack
}


class DetectionEngine:
    """
    Runs all enabled detectors against incoming requests and produces
    a combined risk assessment.

    Usage:
        engine = DetectionEngine()
        events, risk_score = engine.analyze(request)
    """

    def __init__(self):
        """
        Initialize all detectors specified in the ENABLED_DETECTORS config.
        Detectors are instantiated once and reused for all requests.
        """
        self._detectors = []
        for name in Config.ENABLED_DETECTORS:
            name = name.strip()
            if name in DETECTOR_MAP:
                self._detectors.append(DETECTOR_MAP[name]())

    def analyze(self, request: AIRequest) -> tuple[list[SecurityEvent], int]:
        """
        Run all detectors against a request and return combined results.

        Args:
            request: The AI API request to inspect

        Returns:
            A tuple of (list of security events, total risk score)
            - events: All detectors that flagged something (empty if clean)
            - risk_score: Sum of severity weights (0 = no issues found)
        """
        events: list[SecurityEvent] = []

        # Run each detector and collect any events they produce
        for detector in self._detectors:
            event = detector.analyze(request)
            if event:
                events.append(event)

        # Calculate total risk score from all detected events
        risk_score = sum(SEVERITY_SCORES[e.severity] for e in events)

        return events, risk_score
