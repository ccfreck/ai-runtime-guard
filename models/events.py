"""
models/events.py — Data models that define the contract between all components.

Purpose:
    Defines the two core data structures used throughout the system:
    1. AIRequest — the incoming request to be inspected
    2. SecurityEvent — the output produced when misuse is detected

Why:
    Using Pydantic models gives us automatic validation, serialization, and
    type safety. Every detector and the alert manager speak the same language,
    which makes the system easy to extend with new detectors.
"""

from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """
    Risk severity levels for security events.

    Ordered from least to most severe. The numeric mapping is used by the
    detection engine to calculate an overall risk score per request.
    """
    LOW = "LOW"           # Minor anomaly, worth noting but not urgent
    MEDIUM = "MEDIUM"     # Suspicious pattern, should be reviewed
    HIGH = "HIGH"         # Likely malicious or dangerous, needs immediate attention
    CRITICAL = "CRITICAL" # Confirmed attack or data breach in progress


class AIRequest(BaseModel):
    """
    Represents a single AI API request that needs to be inspected.

    This is the input to the detection engine. In production, this data
    would be captured by intercepting the actual API call (e.g., via a proxy
    or middleware) before it reaches the AI provider.
    """
    user: str                                    # Who is making the request
    model: str                                   # Which AI model is being called
    prompt: str                                  # The actual prompt/content sent
    timestamp: datetime = Field(                   # When the request was made
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source_ip: str = "unknown"                   # Origin IP for geo/velocity checks
    token_estimate: int = 0                      # Estimated token count (for cost/limit tracking)


class SecurityEvent(BaseModel):
    """
    Represents a detected security issue.

    Produced by detectors when they find something suspicious. This is the
    output that gets routed to alerts, SIEM systems, and dashboards.
    """
    event: str = "AI_API_MISUSE"                 # Event category (always this for now)
    severity: Severity                           # How dangerous this is
    type: str                                    # Specific detection type (e.g., "SECRET_EXPOSURE")
    user: str                                    # Which user triggered it
    model: str                                   # Which model was being called
    detector: str                                # Which detector found it (for tracing)
    timestamp: datetime = Field(                   # When the event was generated
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: dict = Field(default_factory=dict)  # Detector-specific context (IPs, counts, etc.)
