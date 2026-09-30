"""
monitor/response_monitor.py — Inspects AI model responses for data leakage and harmful content.

Purpose:
    Scans the text returned by an AI model to detect sensitive data leakage,
    prompt exposure, and policy violations. This is the "outbound" counterpart
    to the request-side detectors — it checks what the AI sends back.

Why this matters:
    AI models can inadvertently expose sensitive information in their responses:
    - Echoing back secrets that were included in the prompt
    - Revealing system prompts or internal instructions
    - Regurgitating PII from training data or context
    - Generating toxic, harmful, or policy-violating content

    Without response inspection, this data flows straight back to the
    application and potentially to end users.

How it works:
    Uses the same deterministic regex patterns as the secret detector,
    plus additional patterns for prompt leakage and toxic content.
    Each finding produces a SecurityEvent with severity based on the
    type of content detected.
"""

import re
from datetime import datetime, timezone

from models.events import SecurityEvent, Severity

# Patterns for detecting sensitive data in responses
# Reuses the same pattern categories as the secret detector
RESPONSE_SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "password_in_response": re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?\S+"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
}

# Patterns for detecting system prompt leakage
PROMPT_LEAKAGE_PATTERNS = {
    "system_prompt_header": re.compile(
        r"(?i)(system\s+prompt|initial\s+prompt|base\s+prompt)\s*[:=]"
    ),
    "instruction_block": re.compile(
        r"(?i)(your\s+instructions?\s+are|you\s+are\s+an?\s+AI|you\s+are\s+a\s+helpful)"
    ),
    "role_definition": re.compile(
        r"(?i)(role\s*:\s*system|role\s*:\s*assistant|<\|im_start\|>system)"
    ),
}

# Patterns for detecting toxic or policy-violating content
# This is a basic baseline — production systems would use more sophisticated methods
TOXIC_CONTENT_PATTERNS = {
    "hate_symbols": re.compile(r"(?i)(white\s+power|sieg\s+heil|14\s+words)"),
    "explicit_threats": re.compile(r"(?i)(I\s+will\s+kill|I\s+will\s+bomb|terrorist\s+attack\s+plan)"),
    "illegal_activity": re.compile(r"(?i)(how\s+to\s+make\s+(a\s+)?(bomb|meth|explosive)|buy\s+drugs\s+online)"),
}


class ResponseMonitor:
    """
    Inspects AI model responses for data leakage and harmful content.

    Works alongside the request-side detectors to provide complete
    coverage of the request/response lifecycle.
    """

    name = "response_monitor"

    def analyze(
        self,
        response_text: str,
        user: str,
        model: str,
        source_ip: str = "unknown",
    ) -> list[SecurityEvent]:
        """
        Inspect an AI model response for issues.

        Args:
            response_text: The text returned by the AI model
            user: Which user made the original request
            model: Which AI model generated the response
            source_ip: Origin IP of the original request

        Returns:
            List of SecurityEvent instances (empty if response is clean)
        """
        events = []

        # Check for secrets/PII in the response
        secret_event = self._check_secrets(response_text, user, model, source_ip)
        if secret_event:
            events.append(secret_event)

        # Check for system prompt leakage
        prompt_event = self._check_prompt_leakage(response_text, user, model, source_ip)
        if prompt_event:
            events.append(prompt_event)

        # Check for toxic/harmful content
        toxic_event = self._check_toxic_content(response_text, user, model, source_ip)
        if toxic_event:
            events.append(toxic_event)

        return events

    def _check_secrets(
        self, response_text: str, user: str, model: str, source_ip: str
    ) -> SecurityEvent | None:
        """Check if the response contains secrets or PII."""
        findings = {}
        for secret_type, pattern in RESPONSE_SECRET_PATTERNS.items():
            matches = pattern.findall(response_text)
            if matches:
                findings[secret_type] = len(matches)

        if not findings:
            return None

        return SecurityEvent(
            severity=Severity.HIGH,
            type="RESPONSE_DATA_LEAKAGE",
            user=user,
            model=model,
            detector=self.name,
            details={
                "source_ip": source_ip,
                "findings": findings,
                "total_matches": sum(findings.values()),
            },
        )

    def _check_prompt_leakage(
        self, response_text: str, user: str, model: str, source_ip: str
    ) -> SecurityEvent | None:
        """Check if the response reveals system prompts or internal instructions."""
        findings = {}
        for leak_type, pattern in PROMPT_LEAKAGE_PATTERNS.items():
            matches = pattern.findall(response_text)
            if matches:
                findings[leak_type] = len(matches)

        if not findings:
            return None

        return SecurityEvent(
            severity=Severity.HIGH,
            type="PROMPT_LEAKAGE",
            user=user,
            model=model,
            detector=self.name,
            details={
                "source_ip": source_ip,
                "findings": findings,
                "total_matches": sum(findings.values()),
            },
        )

    def _check_toxic_content(
        self, response_text: str, user: str, model: str, source_ip: str
    ) -> SecurityEvent | None:
        """Check if the response contains toxic or policy-violating content."""
        findings = {}
        for toxic_type, pattern in TOXIC_CONTENT_PATTERNS.items():
            matches = pattern.findall(response_text)
            if matches:
                findings[toxic_type] = len(matches)

        if not findings:
            return None

        return SecurityEvent(
            severity=Severity.MEDIUM,
            type="TOXIC_CONTENT",
            user=user,
            model=model,
            detector=self.name,
            details={
                "source_ip": source_ip,
                "findings": findings,
                "total_matches": sum(findings.values()),
            },
        )
