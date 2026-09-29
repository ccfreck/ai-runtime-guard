"""
config.py — Centralized configuration management for AI Runtime Guard.

Purpose:
    Loads environment variables and exposes them as a single Config class.
    This keeps all tunable settings (rate limits, thresholds, feature flags)
    in one place instead of scattered across the codebase.

Why:
    Security tools need to be tunable without code changes. By reading from
    environment variables, the same code can run in dev, staging, and production
    with different sensitivity levels.
"""

import os
from dotenv import load_dotenv

# Load variables from .env file (if present) into the process environment.
# This lets developers configure the app locally without hardcoding secrets.
load_dotenv()


class Config:
    """Application configuration loaded from environment variables with safe defaults."""

    # Display name for the application (used in logs, health checks, alerts)
    APP_NAME = os.getenv("APP_NAME", "ai-runtime-guard")

    # Controls verbosity of logging. DEBUG for development, INFO/PROD for production.
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # Optional webhook URL (e.g., Slack, PagerDuty, SIEM) where alerts are POSTed.
    # If empty, alerts are only logged to console.
    ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")

    # Maximum requests allowed per user per minute before flagging as rate abuse.
    # 60 RPM = 1 request/second average, which is generous for human users
    # but will catch automated scraping or runaway scripts.
    RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv("RATE_LIMIT_RPM", "60"))

    # Token count above which a single request is considered anomalous.
    # 10,000 tokens ≈ 7,500 words — far more than a typical user prompt.
    TOKEN_ANOMALY_THRESHOLD = int(os.getenv("TOKEN_ANOMALY_THRESHOLD", "10000"))

    # Comma-separated list of detectors to enable. Allows disabling specific
    # detectors without code changes (e.g., "rate,secret" to disable anomaly).
    ENABLED_DETECTORS = os.getenv(
        "ENABLED_DETECTORS", "rate,secret,prompt,token,anomaly"
    ).split(",")
