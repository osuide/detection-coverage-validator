# Rate Limiting

Understand API rate limits and how to handle them gracefully.

## Overview

A13E applies rate limits to ensure fair usage and maintain API performance for all users. Rate limits are based on your subscription tier and apply per API key.

## Rate Limits by Tier

| Tier | Requests per Hour | Scan Limit |
|------|-------------------|------------|
| **Free** | 100 | 4 per week |
| **Individual** (£29/month) | 1,000 | 20 per week |
| **Pro** (£250/month) | 10,000 | 100 per week |
| **Enterprise** | 100,000 | Unlimited |

## Response Headers

Every API response includes rate limit information in the headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed per hour |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the limit resets |

### Example Response Headers

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1704067200
Content-Type: application/json
```

## Handling Rate Limits

When you exceed the rate limit, the API returns a `429 Too Many Requests` response:

```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit of 1000 requests per hour exceeded",
  "limit": 1000,
  "reset_at": "2025-01-01T12:00:00Z"
}
```

The response includes a `Retry-After` header indicating how many seconds to wait:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 3600
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704067200
```

## Best Practices

### 1. Implement Exponential Backoff

When rate limited, wait with exponential backoff:

```python
import time
import httpx

def make_request_with_retry(url: str, headers: dict, max_retries: int = 3):
    """Make request with exponential backoff on rate limiting."""
    for attempt in range(max_retries):
        response = httpx.get(url, headers=headers)

        if response.status_code == 429:
            # Get retry delay from header or use exponential backoff
            retry_after = int(response.headers.get("Retry-After", 2 ** attempt))
            print(f"Rate limited. Retrying in {retry_after} seconds...")
            time.sleep(retry_after)
            continue

        return response

    raise Exception("Max retries exceeded")
```

### 2. Check Remaining Requests

Monitor the `X-RateLimit-Remaining` header to avoid hitting limits:

```python
def check_rate_limit(response):
    """Check and log rate limit status."""
    remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
    limit = int(response.headers.get("X-RateLimit-Limit", 0))

    if remaining < limit * 0.1:  # Less than 10% remaining
        print(f"Warning: Only {remaining} requests remaining")

    return remaining
```

### 3. Batch Requests Where Possible

Instead of making many individual requests, use bulk endpoints where available:

```python
# Bad: Multiple individual requests
for account_id in account_ids:
    response = httpx.get(f"{BASE_URL}/accounts/{account_id}", headers=headers)

# Good: Single request with filtering
response = httpx.get(
    f"{BASE_URL}/accounts",
    headers=headers,
    params={"ids": ",".join(account_ids)}
)
```

### 4. Cache Responses

Cache responses that don't change frequently:

```python
from functools import lru_cache
from datetime import datetime, timedelta

@lru_cache(maxsize=100)
def get_coverage_cached(account_id: str, cache_time: str):
    """Cache coverage data for 5 minutes."""
    response = httpx.get(
        f"{BASE_URL}/accounts/{account_id}/coverage",
        headers=headers
    )
    return response.json()

# Use cache key with 5-minute resolution
cache_key = datetime.now().strftime("%Y%m%d%H%M")[:-1]  # Truncate to 5-min
coverage = get_coverage_cached(account_id, cache_key)
```

### 5. Use Webhooks Instead of Polling

For scan completion, use webhooks or alerts instead of polling:

```python
# Bad: Polling every 10 seconds
while True:
    status = get_scan_status(scan_id)
    if status == "completed":
        break
    time.sleep(10)

# Good: Configure webhook to receive scan completion
# Then wait for webhook notification instead of polling
```

## Scan-Specific Limits

In addition to API rate limits, there are limits on how many scans you can run:

| Tier | Scans per Week |
|------|----------------|
| Free | 4 |
| Individual | 20 |
| Pro | 100 |
| Enterprise | Unlimited |

When you reach the scan limit:

```json
{
  "error": "scan_limit_exceeded",
  "message": "Weekly scan limit of 20 exceeded. Resets on Monday.",
  "limit": 20,
  "used": 20,
  "reset_at": "2025-01-06T00:00:00Z"
}
```

## Upgrading Your Plan

If you consistently hit rate limits, consider upgrading your plan:

1. Log in to the [A13E Dashboard](https://staging.a13e.com)
2. Navigate to **Settings** → **Billing**
3. Click **Upgrade Plan**
4. Select your new tier

Upgrades take effect immediately.

## Enterprise Custom Limits

Enterprise customers can request custom rate limits:

- Higher requests per hour
- Burst capacity for specific operations
- Dedicated API endpoints

Contact [support@a13e.com](mailto:support@a13e.com) to discuss custom limits.

## Next Steps

- [Authentication](./authentication.md) - Set up API keys
- [Quickstart](./quickstart.md) - Make your first API call
