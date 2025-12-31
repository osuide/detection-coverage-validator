# Authentication

Learn how to authenticate with the A13E API using API keys.

## Overview

The A13E API uses API keys for authentication. Every API request must include your API key in the `Authorization` header.

## Creating an API Key

1. Log in to the [A13E Dashboard](https://staging.a13e.com)
2. Navigate to **Settings** → **API Keys**
3. Click **Create API Key**
4. Enter a descriptive name (e.g., "CI/CD Pipeline", "Monitoring Script")
5. Select the required **scopes** for your use case
6. Optionally configure:
   - **Expiration**: Set an automatic expiry date (recommended)
   - **IP Allowlist**: Restrict the key to specific IP addresses or CIDR ranges
7. Click **Create**

**Important**: The full API key is only shown once at creation. Copy it immediately and store it securely.

## API Key Format

API keys follow this format:

```
dcv_live_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

- `dcv_live_` - Prefix identifying this as an A13E API key
- `xxxxxxxx` - Key prefix (visible in the dashboard for identification)
- `xxxx...` - Secret portion (never shown again after creation)

## Using Your API Key

Include your API key in the `Authorization` header with the `Bearer` scheme:

```bash
curl -X GET "https://api.a13e.com/api/v1/accounts" \
  -H "Authorization: Bearer dcv_live_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### Python Example

```python
import httpx

API_KEY = "dcv_live_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
BASE_URL = "https://api.a13e.com/api/v1"

headers = {"Authorization": f"Bearer {API_KEY}"}

response = httpx.get(f"{BASE_URL}/accounts", headers=headers)
print(response.json())
```

### JavaScript Example

```javascript
const API_KEY = 'dcv_live_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
const BASE_URL = 'https://api.a13e.com/api/v1';

const response = await fetch(`${BASE_URL}/accounts`, {
  headers: {
    'Authorization': `Bearer ${API_KEY}`,
  },
});
const data = await response.json();
console.log(data);
```

## Available Scopes

Scopes control what operations an API key can perform. Select only the scopes your integration needs.

| Scope | Description |
|-------|-------------|
| `read:accounts` | View cloud accounts |
| `write:accounts` | Create, update, delete cloud accounts |
| `read:scans` | View scan results and history |
| `write:scans` | Trigger new scans |
| `read:detections` | View discovered detections |
| `write:detections` | Update detection mappings |
| `read:coverage` | View coverage analysis and gaps |
| `read:mappings` | View MITRE ATT&CK mappings |
| `write:mappings` | Update custom mappings |
| `read:reports` | View and download reports |
| `write:reports` | Generate new reports |

## IP Allowlisting

For additional security, you can restrict your API key to specific IP addresses:

- **Single IP**: `192.168.1.100`
- **CIDR range**: `10.0.0.0/24`
- **IPv6**: `2001:db8::1/128`

Add multiple entries to allow multiple IPs or ranges.

When IP allowlisting is enabled, requests from any other IP address will receive a `403 Forbidden` error.

## Key Expiration

Setting an expiration date is recommended for security:

- **CI/CD keys**: 90-180 days
- **Temporary integrations**: 30 days
- **Production services**: 365 days (with regular rotation)

Expired keys return a `401 Unauthorized` error. Create a new key before expiration to avoid service interruption.

## Error Responses

### 401 Unauthorized

The API key is missing, invalid, or expired.

```json
{
  "detail": "Invalid or expired API key"
}
```

### 403 Forbidden

The API key is valid but lacks the required scope, or the request IP is not in the allowlist.

```json
{
  "detail": "Missing required scope: write:scans"
}
```

## Security Best Practices

1. **Never commit API keys to version control**
   - Use environment variables or secret management tools
   - Add `.env` files to your `.gitignore`

2. **Use minimum required scopes**
   - Only grant the permissions your integration actually needs
   - Create separate keys for different integrations

3. **Enable IP allowlisting**
   - Restrict keys to known IP addresses where possible
   - Especially important for production integrations

4. **Set expiration dates**
   - Rotate keys regularly (every 90-180 days)
   - Automated rotation is recommended for critical integrations

5. **Monitor key usage**
   - Review the "Last used" timestamp in the dashboard
   - Revoke unused keys promptly

6. **Revoke compromised keys immediately**
   - If a key may have been exposed, revoke it in the dashboard
   - Create a new key with the same scopes

## Next Steps

- [Rate Limiting](./rate-limiting.md) - Understand API rate limits
- [Quickstart](./quickstart.md) - Run your first API call
