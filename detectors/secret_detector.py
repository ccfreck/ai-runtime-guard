"""
detectors/secret_detector.py — Detects sensitive data leakage in AI API prompts.

Purpose:
    Scans the text of each prompt for patterns that indicate secrets or PII
    are being sent to an AI API. This prevents accidental exposure of credentials,
    personal data, or cryptographic keys to third-party AI providers.

Why this matters:
    If a user pastes a password, API key, or customer data into a prompt,
    that data is sent to an external AI provider's servers. This detector
    catches that before it happens, preventing data breaches and compliance
    violations (GDPR, HIPAA, etc.).

How it works:
    Uses pre-compiled regular expressions to search for known secret formats.
    Each pattern is designed to minimize false positives while catching
    the most common credential types.
"""

import re
from models.events import AIRequest, SecurityEvent, Severity

# Pre-compiled regex patterns for different types of sensitive data.
# These are compiled once at module load for performance.
SECRET_PATTERNS = {
    # AWS access key IDs always start with "AKIA" followed by 16 uppercase alphanumeric chars
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),

    # AWS secret keys are 40-char base64-like strings, often near "aws_secret_access_key ="
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),

    # GitHub personal access tokens start with "ghp_" followed by 36 alphanumeric chars
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),

    # OpenAI API keys start with "sk-" followed by 48 alphanumeric chars
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{48}"),

    # PEM private key headers (RSA, EC, DSA, OpenSSH formats)
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),

    # Passwords written in prompts like "password: hunter2" or "pwd=secret"
    "password_in_prompt": re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?\S+"),

    # Email addresses (PII — could be customer data or internal emails)
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),

    # US Social Security Numbers in standard format (123-45-6789)
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),

    # Credit card numbers (16 digits, optionally spaced or dashed every 4)
    "credit_card": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
}


class SecretDetector:
    """
    Scans prompts for secrets and PII before they reach the AI API.

    Returns a HIGH severity event because secret exposure is always serious —
    even if accidental, the data has left your infrastructure.
    """

    name = "secret_detector"  # Identifier used in events and logs

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        """
        Check the request prompt for any sensitive data patterns.

        Returns:
            SecurityEvent if any secrets/PII found, None if the prompt is clean.
        """
        findings = {}

        # Run each regex pattern against the prompt text
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(request.prompt)
            if matches:
                findings[secret_type] = len(matches)

        # If nothing matched, the prompt is clean — no event needed
        if not findings:
            return None

        # Build and return a security event with details about what was found
        return SecurityEvent(
            severity=Severity.HIGH,  # Secret exposure is always HIGH
            type="SECRET_EXPOSURE",
            user=request.user,
            model=request.model,
            detector=self.name,
            details={
                "source_ip": request.source_ip,
                "findings": findings,           # Which types were found and how many
                "total_matches": sum(findings.values()),  # Total count across all types
            },
        )
