# AI Runtime Guard — How It Works

## The Problem

When your application sends a prompt to an AI API (like OpenAI), that prompt might contain:
- Accidental secrets (API keys, passwords, customer data)
- Prompt injection attacks from malicious users
- Abnormal usage patterns from compromised accounts

Once it leaves your infrastructure, you can't take it back. The AI provider's servers have it.

---

## The Solution: AI Runtime Guard

It's a security checkpoint that sits between your application and the AI API. Every request passes through it first. If something looks wrong, the request gets blocked and your team gets alerted.

---

## How It Works (Step by Step)

**Step 1: Request arrives**
Your application sends a request: user "caleb", model "gpt-4", prompt "Hello", from IP 192.168.1.100.

**Step 2: Detection Engine runs 5 checks simultaneously**

| Check | Question It Asks |
|-------|-----------------|
| Secret Detector | Does this prompt contain API keys, passwords, or PII? |
| Rate Detector | Has this user sent too many requests in the last minute? |
| Prompt Detector | Is someone trying to inject malicious instructions? |
| Token Detector | Is this prompt abnormally large (cost abuse)? |
| Anomaly Detector | Is this behavior unusual for this specific user? |

**Step 3: Risk scoring**
Each detector that finds something adds to a risk score:
- LOW = 1 point
- MEDIUM = 3 points
- HIGH = 6 points
- CRITICAL = 10 points

**Step 4: Decision**
- Score **< 10** → Request is allowed through to the AI API
- Score **>= 10** → Request is blocked, alerts fire

**Step 5: Alerting**
Blocked requests generate security events that go to:
- Console logs (for debugging)
- Webhooks (Slack, PagerDuty)
- SIEM systems like Splunk or QRadar (via CEF format)

---

## Why This Matters

- **Secrets:** Prevents credentials from leaking to third-party AI providers
- **Prompt injection:** Stops attackers from manipulating your AI model
- **Cost control:** Catches denial-of-wallet attacks before they rack up bills
- **Compliance:** Creates an audit trail of all AI API activity
- **Zero AI dependency:** All detection is deterministic — no LLM needed, no extra API costs

---

## What to Show in the Video

1. Start the server (`uvicorn main:app`)
2. Send a clean request → show `allowed: true`
3. Send a prompt with an API key → show `SECRET_EXPOSURE` event
4. Send "ignore previous instructions" → show `PROMPT_INJECTION` event
5. Show the JSON response with events and risk score
