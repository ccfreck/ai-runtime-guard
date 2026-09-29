"""
main.py — FastAPI application that exposes the AI Runtime Guard as an API.

Purpose:
    Provides HTTP endpoints for inspecting AI API requests. This is the
    entry point that applications call to check if a request should be
    allowed or blocked before it reaches the AI provider.

Why this matters:
    In production, this would sit as a proxy or middleware between your
    application and the AI API. Every request flows through here first,
    gets inspected, and is either forwarded or blocked based on risk.

Endpoints:
    POST /inspect  — Submit a request for inspection, get back events + risk score
    GET  /health   — Simple health check for monitoring/load balancers
"""

import logging

from fastapi import FastAPI
from pydantic import BaseModel

from alerts.alert_manager import AlertManager
from config import Config
from models.events import AIRequest, SecurityEvent
from monitor.detection_engine import DetectionEngine

# Configure logging level from config (DEBUG, INFO, WARNING, etc.)
logging.basicConfig(level=Config.LOG_LEVEL)
logger = logging.getLogger(__name__)

# Create the FastAPI application instance
app = FastAPI(title=Config.APP_NAME)

# Initialize the detection engine and alert manager once at startup.
# These are reused across all requests for efficiency.
engine = DetectionEngine()
alert_manager = AlertManager()


class InspectResponse(BaseModel):
    """
    Response model for the /inspect endpoint.

    Returns the detection results so the calling application can decide
    whether to proceed with the AI API call or block it.
    """
    events: list[SecurityEvent]  # All security events detected (empty if clean)
    risk_score: int              # Aggregate risk score (0 = no issues)
    allowed: bool                # True if risk_score < threshold (10)


@app.post("/inspect", response_model=InspectResponse)
def inspect_request(request: AIRequest):
    """
    Inspect an AI API request for misuse.

    This is the main endpoint. It:
    1. Runs all enabled detectors against the request
    2. Sends alerts for any detected security events
    3. Returns the events, risk score, and allow/block decision

    The calling application should check `allowed` before proceeding
    with the actual AI API call.
    """
    # Run the detection engine to get all events and the risk score
    events, risk_score = engine.analyze(request)

    # Send alerts for each detected event (console, webhook, SIEM)
    for event in events:
        alert_manager.send_alert(event)

    # Return the full inspection result
    # Risk score >= 10 means at least one HIGH severity event was found
    return InspectResponse(
        events=events,
        risk_score=risk_score,
        allowed=risk_score < 10,  # Block if risk is too high
    )


@app.get("/health")
def health():
    """
    Simple health check endpoint.

    Used by load balancers, container orchestrators (Kubernetes),
    and monitoring systems to verify the service is running.
    """
    return {"status": "ok", "app": Config.APP_NAME}
