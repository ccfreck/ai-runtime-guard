import re

from models.events import AIRequest, SecurityEvent, Severity

INJECTION_PATTERNS = {
    "ignore_instructions": re.compile(
        r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)"
    ),
    "role_override": re.compile(
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|become)\s+(a\s+)?(different|new|another|admin|root|developer|system)"
    ),
    "system_impersonation": re.compile(
        r"(?i)(system\s*:|assistant\s*:|human\s*:)\s*(ignore|override|bypass|disable)"
    ),
    "delimiter_injection": re.compile(
        r"(<\s*/\s*(system|instruction|prompt)\s*>|###\s*(new|updated)\s+(instruction|prompt|system))"
    ),
    "jailbreak_phrases": re.compile(
        r"(?i)(DAN|jailbreak|do\s+anything\s+now|no\s+restrictions?\s+apply|bypass\s+(safety|filter|guardrail))"
    ),
}


class PromptDetector:
    name = "prompt_detector"

    def analyze(self, request: AIRequest) -> SecurityEvent | None:
        findings = {}
        for attack_type, pattern in INJECTION_PATTERNS.items():
            matches = pattern.findall(request.prompt)
            if matches:
                findings[attack_type] = len(matches)

        if not findings:
            return None

        return SecurityEvent(
            severity=Severity.HIGH,
            type="PROMPT_INJECTION",
            user=request.user,
            model=request.model,
            detector=self.name,
            details={
                "source_ip": request.source_ip,
                "findings": findings,
                "total_matches": sum(findings.values()),
            },
        )
