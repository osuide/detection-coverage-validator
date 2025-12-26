# Security Findings Remediation Plan

This plan addresses the three findings from the review: API key auth mismatch, admin MFA secret encryption, and admin IP allowlist trust. Because staging has no MFA users and no API keys yet, the plan opts for immediate changes with no migration path.

## Goals

- Restore API key authentication without breaking existing keys.
- Use production-grade encryption for admin MFA secrets and reduce secret exposure risk.
- Ensure admin IP allowlist enforcement cannot be bypassed via spoofed headers.

## Finding 1: API key hash mismatch (High)

### Root cause
API keys are stored with a bcrypt hash, but authentication looks up a SHA-256 hash of the raw key. This makes every lookup fail.

### Remediation steps (no-migration)
1. **Update API key creation to store SHA-256**
   - Store SHA-256 at creation time in `APIKey.key_hash`.
2. **Update API key authentication to use SHA-256 only**
   - Remove bcrypt usage for API keys in authentication.
3. **Enforce a single hash strategy**
   - Keep `key_hash` as the SHA-256 value and remove any bcrypt assumptions in code.

### Validation
- Unit tests:
  - New API key can authenticate via SHA-256 lookup.
- Integration tests:
  - Create key → use key → confirm `usage_count` increments and last_used fields update.

### Compatibility safeguards
- None required in staging because no API keys exist yet.

## Finding 2: Admin MFA secret encryption (High)

### Root cause
Admin MFA secrets are “encrypted” with XOR using the app secret, which is reversible and not suitable for production.

### Remediation steps (no-migration)
1. **Adopt strong encryption for admin MFA secrets**
   - Use the same `credential_encryption_key` with Fernet (or KMS envelope encryption).
   - Prefer KMS for production, with a local fallback for dev.
2. **Update admin setup flow**
   - Ensure new secrets are stored only with the strong encryption method.
3. **Add configuration checks**
   - If `credential_encryption_key` is missing in production, fail startup for admin MFA features.

### Validation
- Unit tests:
  - New MFA secret round-trips with Fernet.
  - Incorrect key fails decrypt and does not silently accept.
- Integration tests:
  - Admin MFA setup → verify TOTP → login works.

### Compatibility safeguards
- None required in staging because no MFA users exist yet.

## Finding 3: Admin IP allowlist trust (Medium)

### Root cause
The admin auth endpoint trusts `X-Forwarded-For` directly, enabling header spoofing if the service is accessible without a trusted proxy that strips/overwrites the header.

### Remediation steps (best practice)
1. **Centralize trusted proxy handling**
   - Implement a shared function to resolve client IP that:
     - Uses `X-Forwarded-For` only when the immediate peer is trusted.
     - Falls back to `request.client.host` when untrusted.
2. **Add explicit proxy trust configuration**
   - `trusted_proxy_cidrs`: list of CIDR ranges for ingress proxies (e.g., ALB/NLB, CloudFront, internal gateways).
   - `trust_proxy_headers`: boolean flag to enable forwarded header parsing in production.
   - Default behavior: `trust_proxy_headers=false` unless explicitly enabled.
3. **Parse standard forwarded headers safely**
   - Prefer RFC 7239 `Forwarded` when present; otherwise use `X-Forwarded-For`.
   - When `trust_proxy_headers=true`, take the leftmost client IP only after verifying the request came from a trusted proxy.
4. **Use the shared resolver in admin auth**
   - Replace direct use of `X-Forwarded-For` in admin routes.
5. **Document deployment expectations**
   - Admin endpoints must be behind a trusted proxy that strips/overwrites `X-Forwarded-For`.
   - Ingress should restrict direct access to the admin service from the public internet.

### Validation
- Unit tests:
  - When trust is disabled, ignore `X-Forwarded-For`.
  - When trust is enabled and proxy is trusted, use forwarded client IP.
  - Untrusted proxy IPs do not influence resolved client IP.
- Integration tests:
  - Admin login allowed from allowlisted IP.
  - Admin login denied when `X-Forwarded-For` is spoofed.
  - Admin login allowed when `Forwarded` header is provided by trusted proxy.

### Compatibility safeguards
- Default to safe behavior in production.
- Provide config to keep current behavior for legacy deployments behind known proxies.

## Rollout Plan (staging, no-migration)

1. **Apply fixes directly**
   - API key creation/auth uses SHA-256 only.
   - Admin MFA secrets use strong encryption only.
   - Admin IP allowlist uses trusted proxy-aware IP resolution.
2. **Add basic observability**
   - Admin IP deny reasons (no allowlist match).

## Risks and Mitigations

- **Risk**: Admin MFA secrets become unreadable due to misconfiguration.
  - **Mitigation**: Validate encryption key at startup; fail fast in production.
- **Risk**: Admin login blocked due to proxy misconfiguration.
  - **Mitigation**: Provide explicit trusted proxy configuration and clear docs.

## Success Criteria

- API key auth succeeds for both existing and newly created keys.
- Admin MFA secrets are stored with strong encryption and legacy secrets are migrated.
- Admin IP allowlist enforcement is based on trusted client IP, not spoofed headers.
