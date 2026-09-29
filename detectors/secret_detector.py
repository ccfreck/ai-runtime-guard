import re
from models.events import AIRequest, SecurityEvent, Severity

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "password_in_prompt": re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?\S+"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
}


class SecretDetector:
    name = "secret_detector"

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        findings = {}
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(request.prompt)
            if matches:
                findings[secret_type] = len(matches)

        if not findings:
            return None

        return SecurityEvent(
            severity=Severity.HIGH,
            type="SECRET_EXPOSURE",
            user=request.user,
            model=request.model,
            detector=self.name,
            details={
                "source_ip": request.source_ip,
                "findings": findings,
                "total_matches": sum(findings.values()),
            },
        )
