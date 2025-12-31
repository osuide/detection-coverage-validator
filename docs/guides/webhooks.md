# Alerts and Notifications

Learn how to receive alerts when your detection coverage changes.

## Overview

A13E can send notifications when important events occur, such as:

- Scan completion
- New coverage gaps detected
- Compliance drift (controls failing)
- Detection health changes

## Alert Channels

A13E supports multiple notification channels:

| Channel | Use Case | Setup |
|---------|----------|-------|
| **Email** | Personal notifications | Built-in, uses your account email |
| **Slack** | Team notifications | Requires webhook URL |
| **Webhook** | Custom integrations | Any HTTPS endpoint |

## Configuring Alerts

### Via the Dashboard

1. Log in to [A13E](https://staging.a13e.com)
2. Navigate to **Settings** → **Alerts**
3. Click **Create Alert Rule**
4. Configure:
   - **Name**: Descriptive name
   - **Event Type**: What triggers the alert
   - **Conditions**: Optional filters (e.g., priority = critical)
   - **Channels**: Where to send notifications

### Via the API

```bash
# Create an alert rule
curl -X POST "https://api.a13e.com/api/v1/alerts" \
  -H "Authorization: Bearer $A13E_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Critical Gap Alert",
    "event_type": "coverage.gap_detected",
    "conditions": {
      "priority": "critical"
    },
    "channels": [
      {
        "type": "slack",
        "webhook_url": "https://hooks.slack.com/services/xxx/yyy/zzz"
      }
    ],
    "enabled": true
  }'
```

## Event Types

### Scan Events

| Event | Description |
|-------|-------------|
| `scan.started` | A scan has been triggered |
| `scan.completed` | A scan finished successfully |
| `scan.failed` | A scan encountered an error |

### Coverage Events

| Event | Description |
|-------|-------------|
| `coverage.gap_detected` | A new coverage gap was identified |
| `coverage.gap_resolved` | A previously open gap was closed |
| `coverage.percentage_changed` | Overall coverage percentage changed |

### Compliance Events

| Event | Description |
|-------|-------------|
| `compliance.control_failed` | A Security Hub control changed to FAILED |
| `compliance.control_passed` | A previously failed control now passes |
| `compliance.drift_detected` | Multiple controls changed status |

### Detection Events

| Event | Description |
|-------|-------------|
| `detection.health_degraded` | A detection's health status worsened |
| `detection.disabled` | A detection rule was disabled |
| `detection.new_discovered` | A new detection was found during scan |

## Webhook Payload Format

When using webhook channels, A13E sends a POST request with this payload:

```json
{
  "id": "evt_abc123xyz",
  "type": "coverage.gap_detected",
  "created_at": "2025-01-01T12:00:00Z",
  "organization_id": "org_xyz789",
  "data": {
    "account_id": "acc_abc123",
    "account_name": "Production AWS",
    "technique_id": "T1078.004",
    "technique_name": "Cloud Accounts",
    "tactic": "Persistence",
    "priority": "critical",
    "previous_confidence": 0.75,
    "current_confidence": 0.35
  }
}
```

### Webhook Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` |
| `X-A13E-Event` | Event type (e.g., `coverage.gap_detected`) |
| `X-A13E-Signature` | HMAC-SHA256 signature for verification |
| `X-A13E-Timestamp` | Unix timestamp when event was generated |

## Verifying Webhook Signatures

To verify that a webhook request came from A13E, check the signature:

### Python Example

```python
import hmac
import hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    """Verify A13E webhook signature."""
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature)

# In your webhook handler
@app.post("/webhooks/a13e")
async def handle_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("X-A13E-Signature")
    secret = os.environ["A13E_WEBHOOK_SECRET"]

    if not verify_webhook(payload, signature, secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = json.loads(payload)
    # Process the event...
```

## Slack Integration

### Setting Up Slack Alerts

1. Create a Slack Incoming Webhook:
   - Go to your Slack workspace settings
   - Create a new app or use an existing one
   - Add an Incoming Webhook
   - Copy the webhook URL

2. Add to A13E:
   - Go to **Settings** → **Alerts**
   - Create an alert rule
   - Select **Slack** as the channel
   - Paste your webhook URL

### Slack Message Format

A13E sends formatted Slack messages:

```
🚨 Critical Coverage Gap Detected

Account: Production AWS
Technique: T1078.004 - Cloud Accounts
Tactic: Persistence
Priority: Critical

View in A13E →
```

## Email Notifications

Email alerts are sent to your account email address. You can configure:

- **Digest mode**: Receive a daily summary instead of individual alerts
- **Quiet hours**: Suppress non-critical alerts during specified hours
- **Severity filter**: Only receive alerts above a certain priority

## Testing Alerts

### Test via Dashboard

1. Go to **Settings** → **Alerts**
2. Click the **Test** button on any alert rule
3. A test notification will be sent to all configured channels

### Test via API

```bash
# Send a test alert
curl -X POST "https://api.a13e.com/api/v1/alerts/{alert_id}/test" \
  -H "Authorization: Bearer $A13E_API_KEY"
```

## Best Practices

1. **Filter by priority**: Only alert on critical/high priority gaps to avoid alert fatigue
2. **Use separate channels**: Route critical alerts to different channels than informational ones
3. **Verify signatures**: Always verify webhook signatures in production
4. **Handle retries**: A13E retries failed webhook deliveries up to 3 times
5. **Respond quickly**: Return a 2xx status within 10 seconds to acknowledge receipt

## Troubleshooting

### Webhook Not Receiving Events

1. Check the webhook URL is correct and HTTPS
2. Verify the endpoint returns 2xx within 10 seconds
3. Check firewall rules allow inbound from A13E IPs
4. Review the alert rule conditions

### Signature Verification Failing

1. Ensure you're using the raw request body (not parsed JSON)
2. Verify the webhook secret matches exactly
3. Check for any request body modification by proxies

## Next Steps

- [Authentication](./authentication.md) - Set up API keys
- [Rate Limiting](./rate-limiting.md) - Understand request limits
