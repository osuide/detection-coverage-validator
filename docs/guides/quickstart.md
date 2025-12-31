# Quickstart

Get started with the A13E API in 5 minutes.

## Prerequisites

- An A13E account ([sign up](https://staging.a13e.com/signup))
- At least one connected AWS account
- An API key with appropriate scopes

## Step 1: Create an API Key

1. Log in to [A13E](https://staging.a13e.com)
2. Go to **Settings** → **API Keys**
3. Click **Create API Key**
4. Name it (e.g., "Quickstart Test")
5. Select scopes: `read:accounts`, `read:scans`, `write:scans`, `read:coverage`
6. Click **Create** and copy the key

## Step 2: Make Your First Request

### Using curl

```bash
# Set your API key
export A13E_API_KEY="dcv_live_xxxxxxxx_xxxxxxxxxxxxxx"

# List your cloud accounts
curl -s "https://api.a13e.com/api/v1/accounts" \
  -H "Authorization: Bearer $A13E_API_KEY" | jq
```

### Using Python

```python
import httpx

API_KEY = "dcv_live_xxxxxxxx_xxxxxxxxxxxxxx"
BASE_URL = "https://api.a13e.com/api/v1"

headers = {"Authorization": f"Bearer {API_KEY}"}

# List cloud accounts
response = httpx.get(f"{BASE_URL}/accounts", headers=headers)
accounts = response.json()

for account in accounts["items"]:
    print(f"Account: {account['name']} ({account['provider']})")
```

### Using JavaScript

```javascript
const API_KEY = 'dcv_live_xxxxxxxx_xxxxxxxxxxxxxx';
const BASE_URL = 'https://api.a13e.com/api/v1';

async function listAccounts() {
  const response = await fetch(`${BASE_URL}/accounts`, {
    headers: { 'Authorization': `Bearer ${API_KEY}` },
  });
  const data = await response.json();

  data.items.forEach(account => {
    console.log(`Account: ${account.name} (${account.provider})`);
  });
}

listAccounts();
```

## Step 3: Trigger a Scan

Once you have your account ID, trigger a scan:

### curl

```bash
# Get the first account ID
ACCOUNT_ID=$(curl -s "https://api.a13e.com/api/v1/accounts" \
  -H "Authorization: Bearer $A13E_API_KEY" | jq -r '.items[0].id')

# Trigger a scan
curl -X POST "https://api.a13e.com/api/v1/accounts/$ACCOUNT_ID/scans" \
  -H "Authorization: Bearer $A13E_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"regions": ["eu-west-2"]}' | jq
```

### Python

```python
# Get the first account
accounts = httpx.get(f"{BASE_URL}/accounts", headers=headers).json()
account_id = accounts["items"][0]["id"]

# Trigger a scan
scan_response = httpx.post(
    f"{BASE_URL}/accounts/{account_id}/scans",
    headers=headers,
    json={"regions": ["eu-west-2"]}
)
scan = scan_response.json()
print(f"Scan started: {scan['id']}")
```

## Step 4: Check Scan Status

Poll for scan completion:

### curl

```bash
SCAN_ID="<scan-id-from-previous-step>"

curl -s "https://api.a13e.com/api/v1/scans/$SCAN_ID" \
  -H "Authorization: Bearer $A13E_API_KEY" | jq '.status'
```

### Python

```python
import time

scan_id = scan["id"]

while True:
    status_response = httpx.get(
        f"{BASE_URL}/scans/{scan_id}",
        headers=headers
    )
    status = status_response.json()

    print(f"Status: {status['status']} ({status.get('progress_percent', 0)}%)")

    if status["status"] == "completed":
        print(f"Scan complete! Found {status['detections_found']} detections")
        break
    elif status["status"] == "failed":
        print(f"Scan failed: {status.get('error_message')}")
        break

    time.sleep(10)
```

## Step 5: Get Coverage Analysis

View your MITRE ATT&CK coverage:

### curl

```bash
curl -s "https://api.a13e.com/api/v1/accounts/$ACCOUNT_ID/coverage" \
  -H "Authorization: Bearer $A13E_API_KEY" | jq
```

### Python

```python
coverage = httpx.get(
    f"{BASE_URL}/accounts/{account_id}/coverage",
    headers=headers
).json()

print(f"Coverage: {coverage['coverage_percentage']}%")
print(f"Covered techniques: {coverage['covered_count']}")
print(f"Partial coverage: {coverage['partial_count']}")
print(f"Gaps: {coverage['gap_count']}")
```

## Step 6: View Coverage Gaps

Get prioritised coverage gaps:

### curl

```bash
curl -s "https://api.a13e.com/api/v1/accounts/$ACCOUNT_ID/coverage/gaps?priority=critical" \
  -H "Authorization: Bearer $A13E_API_KEY" | jq
```

### Python

```python
gaps = httpx.get(
    f"{BASE_URL}/accounts/{account_id}/coverage/gaps",
    headers=headers,
    params={"priority": "critical"}
).json()

for gap in gaps["items"]:
    print(f"[{gap['priority']}] {gap['technique_id']}: {gap['technique_name']}")
```

## Complete Example

Here's a complete Python script that runs through all the steps:

```python
#!/usr/bin/env python3
"""A13E API Quickstart Example"""

import os
import time
import httpx

API_KEY = os.environ.get("A13E_API_KEY")
BASE_URL = "https://api.a13e.com/api/v1"

if not API_KEY:
    print("Error: Set A13E_API_KEY environment variable")
    exit(1)

headers = {"Authorization": f"Bearer {API_KEY}"}

# 1. List accounts
print("Fetching cloud accounts...")
accounts = httpx.get(f"{BASE_URL}/accounts", headers=headers).json()

if not accounts["items"]:
    print("No accounts found. Connect an AWS account first.")
    exit(1)

account = accounts["items"][0]
print(f"Using account: {account['name']} ({account['id']})")

# 2. Trigger scan
print("\nTriggering scan...")
scan = httpx.post(
    f"{BASE_URL}/accounts/{account['id']}/scans",
    headers=headers,
    json={"regions": ["eu-west-2"]}
).json()
print(f"Scan started: {scan['id']}")

# 3. Wait for completion
print("\nWaiting for scan to complete...")
while True:
    status = httpx.get(f"{BASE_URL}/scans/{scan['id']}", headers=headers).json()

    if status["status"] == "completed":
        print(f"Scan complete! Found {status['detections_found']} detections")
        break
    elif status["status"] == "failed":
        print(f"Scan failed: {status.get('error_message')}")
        exit(1)

    print(f"  Progress: {status.get('progress_percent', 0)}%")
    time.sleep(10)

# 4. Get coverage
print("\nFetching coverage analysis...")
coverage = httpx.get(
    f"{BASE_URL}/accounts/{account['id']}/coverage",
    headers=headers
).json()

print(f"Coverage: {coverage['coverage_percentage']}%")
print(f"  Covered: {coverage['covered_count']} techniques")
print(f"  Partial: {coverage['partial_count']} techniques")
print(f"  Gaps: {coverage['gap_count']} techniques")

# 5. Get critical gaps
print("\nCritical coverage gaps:")
gaps = httpx.get(
    f"{BASE_URL}/accounts/{account['id']}/coverage/gaps",
    headers=headers,
    params={"priority": "critical", "limit": 5}
).json()

for gap in gaps["items"][:5]:
    print(f"  [{gap['technique_id']}] {gap['technique_name']}")

print("\nDone!")
```

## Next Steps

- [Authentication](./authentication.md) - Learn about API key scopes
- [Rate Limiting](./rate-limiting.md) - Understand request limits
- [API Reference](/api/openapi.json) - Full API documentation
