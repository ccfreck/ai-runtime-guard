from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AIRequest(BaseModel):
    user: str
    model: str
    prompt: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = "unknown"
    token_estimate: int = 0


class SecurityEvent(BaseModel):
    event: str = "AI_API_MISUSE"
    severity: Severity
    type: str
    user: str
    model: str
    detector: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict = Field(default_factory=dict)
