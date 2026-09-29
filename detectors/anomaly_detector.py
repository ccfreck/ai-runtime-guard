import statistics
from collections import defaultdict

from models.events import AIRequest, SecurityEvent, Severity


class AnomalyDetector:
    name = "anomaly_detector"

    def __init__(self):
        self._user_tokens: dict[str, list[int]] = defaultdict(list)
        self._user_models: dict[str, set[str]] = defaultdict(set)

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        findings = {}

        # Check for new model usage
        if (
            request.user in self._user_models
            and request.model not in self._user_models[request.user]
        ):
            findings["new_model"] = request.model
        self._user_models[request.user].add(request.model)

        # Check for token anomaly using z-score
        token_history = self._user_tokens[request.user]
        if len(token_history) >= 5:
            mean = statistics.mean(token_history)
            stdev = statistics.stdev(token_history) if len(token_history) > 1 else 0
            if stdev > 0:
                z_score = (request.token_estimate - mean) / stdev
                if z_score > 3:
                    findings["token_z_score"] = round(z_score, 2)
                    findings["token_mean"] = round(mean, 2)
                    findings["token_stdev"] = round(stdev, 2)

        self._user_tokens[request.user].append(request.token_estimate)

        if not findings:
            return None

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
