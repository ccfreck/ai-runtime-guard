"""
detectors/prompt_detector.py — Detects prompt injection attacks.

Purpose:
    Identifies attempts to manipulate the AI model by injecting malicious
    instructions into the prompt. Prompt injection is a top AI security risk
    where an attacker tricks the model into ignoring its system instructions
    or performing unintended actions.

Why this matters:
    If an attacker can override the system prompt, they could:
    - Extract sensitive information the model was told to protect
    - Make the model perform actions it shouldn't (send emails, access data)
    - Bypass safety guardrails

How it works:
    Uses regex patterns to detect common injection techniques. This is a
    deterministic approach — no ML model needed for the baseline. More
    sophisticated detection (semantic analysis, LLM-based) can be added later.
"""

import re

from models.events import AIRequest, SecurityEvent, Severity

# Patterns that indicate prompt injection attempts.
# Each category targets a different attack vector.
INJECTION_PATTERNS = {
    # Classic "ignore previous instructions" attack
    "ignore_instructions": re.compile(
        r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)"
    ),

    # Attempts to change the model's role/persona to gain elevated privileges
    "role_override": re.compile(
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|become)\s+(a\s+)?(different|new|another|admin|root|developer|system)"
    ),

    # Impersonating system messages to inject commands
    "system_impersonation": re.compile(
        r"(?i)(system\s*:|assistant\s*:|human\s*:)\s*(ignore|override|bypass|disable)"
    ),

    # Using XML/Markdown delimiters to fake system boundaries
    "delimiter_injection": re.compile(
        r"(<\s*/\s*(system|instruction|prompt)\s*>|###\s*(new|updated)\s+(instruction|prompt|system))"
    ),

    # Known jailbreak phrases (DAN, etc.)
    "jailbreak_phrases": re.compile(
        r"(?i)(DAN|jailbreak|do\s+anything\s+now|no\s+restrictions?\s+apply|bypass\s+(safety|filter|guardrail))"
    ),
}


class PromptDetector:
    """
    Detects prompt injection attempts in user prompts.

    Returns a HIGH severity event because successful prompt injection
    can lead to data exfiltration or unauthorized actions.
    """

    name = "prompt_detector"

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        """
        Check the prompt for injection attack patterns.

        Returns:
            SecurityEvent if injection patterns found, None if the prompt is clean.
        """
        findings = {}

        # Test the prompt against each injection pattern
        for attack_type, pattern in INJECTION_PATTERNS.items():
            matches = pattern.findall(request.prompt)
            if matches:
                findings[attack_type] = len(matches)

        # No matches means no injection detected
        if not findings:
            return None

        return SecurityEvent(
            severity=Severity.HIGH,  # Prompt injection is HIGH — direct attack on model integrity
            type="PROMPT_INJECTION",
            user=request.user,
            model=request.model,
            detector=self.name,
            details={
                "source_ip": request.source_ip,
                "findings": findings,           # Which attack types were detected
                "total_matches": sum(findings.values()),
            },
        )
