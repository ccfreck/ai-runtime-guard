import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    APP_NAME = os.getenv("APP_NAME", "ai-runtime-guard")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")
    RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv("RATE_LIMIT_RPM", "60"))
    TOKEN_ANOMALY_THRESHOLD = int(os.getenv("TOKEN_ANOMALY_THRESHOLD", "10000"))
    ENABLED_DETECTORS = os.getenv(
        "ENABLED_DETECTORS", "rate,secret,prompt,token,anomaly"
    ).split(",")
