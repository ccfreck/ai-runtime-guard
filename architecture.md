# AI Runtime Guard — Architecture

## System Flow

```mermaid
flowchart TD
    A[Application] -->|AI API Request| B[AI Runtime Guard]
    B --> C[Request Monitor]
    C --> D[Detection Engine]
    D --> E[Rate Detector]
    D --> F[Secret Detector]
    D --> G[Prompt Detector]
    D --> H[Token Detector]
    D --> I[Anomaly Detector]
    E --> J{Risk Assessment}
    F --> J
    G --> J
    H --> J
    I --> J
    J -->|Allowed| K[AI API]
    J -->|Blocked| L[Alert / SIEM]
    L --> M[Alert Manager]
    M --> N[Webhook / Dashboard]
```

## Component Overview

| Component | Purpose |
|-----------|---------|
| Request Monitor | Intercepts and normalizes incoming AI API requests |
| Detection Engine | Orchestrates all detectors and aggregates results |
| Rate Detector | Flags abnormal request frequency per user/IP |
| Secret Detectector | Detects credentials, API keys, and PII in prompts |
| Prompt Detector | Identifies prompt injection attempts |
| Token Detector | Flags abnormal token consumption |
| Anomaly Detector | Statistical behavioral analysis per user |
| Alert Manager | Routes security events to webhooks, SIEM, or dashboard |

## Data Model

```mermaid
classDiagram
    class AIRequest {
        +str user
        +str model
        +str prompt
        +datetime timestamp
        +str source_ip
        +int token_estimate
    }
    class SecurityEvent {
        +str event
        +Severity severity
        +str type
        +str user
        +str model
        +str detector
        +datetime timestamp
        +dict details
    }
    class Severity {
        <<enumeration>>
        LOW
        MEDIUM
        HIGH
        CRITICAL
    }
    AIRequest --> SecurityEvent : analyzed by
    SecurityEvent --> Severity : has
```
