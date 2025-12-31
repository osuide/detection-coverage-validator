# API Keys

Generate and manage API keys for programmatic access to the A13E platform.

## TL;DR

- **API keys** enable automation, CI/CD integration, and custom tooling
- **Scopes** limit what each key can access (e.g., read-only, scans, accounts)
- **IP allowlists** restrict which networks can use each key
- **Keys are shown once** at creation—store them securely

---

## Before You Start

- A13E account with **Individual**, **Pro**, or **Enterprise** subscription
- API access is not available on the Free plan

---

## Creating an API Key

1. Navigate to **Settings** → **API Keys**
2. Click **Create API Key**
3. Configure your key:

### Name

Give your key a descriptive name that identifies its purpose:
- `CI/CD Pipeline`
- `Monitoring Service`
- `Weekly Reports Script`

### Permissions (Scopes)

Select which operations this key can perform:

| Scope | Description |
|-------|-------------|
| `accounts:read` | View cloud accounts |
| `accounts:write` | Add, update, delete cloud accounts |
| `scans:read` | View scan results and history |
| `scans:write` | Trigger new scans |
| `coverage:read` | View coverage data and gaps |
| `detections:read` | View discovered detections |
| `reports:read` | Generate and download reports |

> **Tip**: Follow the principle of least privilege. Only grant the scopes your integration actually needs.

If you select no scopes, the key will have **full access** to all operations. We recommend always selecting specific scopes.

### Expiration

Choose when the key should automatically expire:

| Option | Best For |
|--------|----------|
| **Never expires** | Long-running services (use with IP restrictions) |
| **30 days** | Temporary integrations, testing |
| **60 days** | Short-term projects |
| **90 days** | Quarterly rotation schedule |
| **180 days** | Semi-annual rotation |
| **1 year** | Annual rotation schedule |

### IP Allowlist (Recommended)

Restrict the key to specific IP addresses or CIDR ranges for additional security:

```
192.168.1.100
10.0.0.0/24
203.0.113.50
```

Enter one IP or CIDR range per line, or comma-separated.

When enabled, API requests from any other IP address will be rejected with a 403 Forbidden error.

4. Click **Create Key**

---

## Saving Your API Key

**Important**: Your API key is displayed only once at creation.

After clicking **Create Key**, you'll see a yellow alert box with your key:

```
a13e_sk_live_xxxxxxxxxxxxxxxxxxxx
```

1. **Copy** the key immediately using the copy button
2. **Store** it in a secure location:
   - Password manager (1Password, LastPass, etc.)
   - Secrets manager (AWS Secrets Manager, HashiCorp Vault)
   - CI/CD secrets (GitHub Actions secrets, GitLab CI variables)
3. Click **I've saved my key** to dismiss the alert

If you lose a key, you'll need to revoke it and create a new one.

---

## Using Your API Key

Include your API key in the `Authorization` header of API requests:

```bash
curl -H "Authorization: Bearer a13e_sk_live_xxxx" \
     https://api.a13e.com/v1/coverage
```

### Example: Trigger a Scan

```bash
curl -X POST \
     -H "Authorization: Bearer a13e_sk_live_xxxx" \
     -H "Content-Type: application/json" \
     -d '{"cloud_account_id": "acc_xxxxx"}' \
     https://api.a13e.com/v1/scans
```

### Example: Get Coverage Summary

```bash
curl -H "Authorization: Bearer a13e_sk_live_xxxx" \
     https://api.a13e.com/v1/coverage?cloud_account_id=acc_xxxxx
```

---

## Managing API Keys

### Viewing Your Keys

Navigate to **Settings** → **API Keys** to see all your keys:

| Column | Description |
|--------|-------------|
| **Name** | The name you gave the key |
| **Prefix** | First few characters (for identification) |
| **Scopes** | Number of permissions granted |
| **Last used** | When the key was last used |
| **Requests** | Total API calls made with this key |
| **Expires** | Expiration date or "Never" |

### Revoking a Key

To revoke a compromised or unused key:

1. Find the key in your list
2. Click the **Trash** icon
3. Confirm the revocation

**Warning**: Revoking a key is immediate and permanent. Any integrations using that key will stop working immediately.

Revoked keys remain visible in your list (marked as "Revoked") for audit purposes.

---

## Security Best Practices

### 1. Use Scoped Keys

Never use full-access keys when limited scopes will do:

```
# Bad: Full access for a reporting script
a13e_sk_live_xxxx (no scopes = full access)

# Good: Read-only access for reporting
a13e_sk_live_xxxx (scopes: coverage:read, reports:read)
```

### 2. Enable IP Restrictions

For production integrations, always restrict by IP:

- Add your CI/CD runner IPs
- Add your monitoring server IPs
- Use CIDR notation for IP ranges

### 3. Rotate Keys Regularly

Set expiration dates and rotate keys on a schedule:

| Environment | Recommended Rotation |
|-------------|---------------------|
| Production | Every 90 days |
| Development | Every 30 days |
| CI/CD | Every 90-180 days |

### 4. Use Environment Variables

Never hardcode API keys in your code:

```bash
# Good
export A13E_API_KEY="a13e_sk_live_xxxx"
curl -H "Authorization: Bearer $A13E_API_KEY" ...

# Bad
curl -H "Authorization: Bearer a13e_sk_live_xxxx" ...
```

### 5. Monitor Key Usage

Regularly check the **Last used** and **Requests** columns:

- Unused keys should be revoked
- Unexpected usage spikes may indicate compromise

---

## Common Questions

**Q: Can I see my key again after creation?**

A: No. For security, keys are only shown once. If you lose a key, revoke it and create a new one.

**Q: What happens when a key expires?**

A: API requests using an expired key receive a 401 Unauthorized error. The key remains in your list for reference.

**Q: How many keys can I create?**

A: There's no hard limit, but we recommend keeping the number manageable. Create separate keys for different integrations rather than sharing one key.

**Q: Can I update a key's scopes or IP restrictions?**

A: No. To change a key's configuration, revoke it and create a new one with the desired settings.

**Q: What's the rate limit for API requests?**

A: Rate limits depend on your subscription tier. Individual: 100 requests/minute. Pro: 500 requests/minute. Enterprise: Custom limits.

---

## Troubleshooting

### 401 Unauthorized

- Check the key is copied correctly (no extra spaces)
- Verify the key hasn't been revoked or expired
- Ensure you're using `Bearer` authentication

### 403 Forbidden

- Check if IP restrictions are blocking your request
- Verify the key has the required scope for the endpoint
- Confirm your subscription includes API access

### 429 Too Many Requests

- You've exceeded the rate limit
- Wait and retry with exponential backoff
- Consider upgrading your plan for higher limits

---

## Next Steps

- [Running Scans](./running-scans.md) - Learn about scan options you can automate
- [Using the Dashboards](./using-dashboards.md) - Understand what data is available via API
- [Billing & Subscription](./billing-subscription.md) - Check API access for your plan
