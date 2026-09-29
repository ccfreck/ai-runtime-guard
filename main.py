import logging

from fastapi import FastAPI
from pydantic import BaseModel

from alerts.alert_manager import AlertManager
from config import Config
from models.events import AIRequest, SecurityEvent
from monitor.detection_engine import DetectionEngine

logging.basicConfig(level=Config.LOG_LEVEL)
logger = logging.getLogger(__name__)

app = FastAPI(title=Config.APP_NAME)
engine = DetectionEngine()
alert_manager = AlertManager()


class InspectResponse(BaseModel):
    events: list[SecurityEvent]
    risk_score: int
    allowed: bool


@app.post("/inspect", response_model=InspectResponse)
def inspect_request(request: AIRequest):
    events, risk_score = engine.analyze(request)

    for event in events:
        alert_manager.send_alert(event)

    return InspectResponse(
        events=events,
        risk_score=risk_score,
        allowed=risk_score < 10,
    )


@app.get("/health")
def health():
    return {"status": "ok", "app": Config.APP_NAME}
