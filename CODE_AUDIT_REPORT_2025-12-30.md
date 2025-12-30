# A13E Detection Coverage Validator - Code Audit Report

**Date:** 30 December 2025
**Auditor:** Claude Code (claude-opus-4-5-20251101)
**Profile:** A13E Project-Specific Review

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Overall Health Score** | 7/10 |
| **Critical Issues** | 1 |
| **High Priority Issues** | 2 |
| **Medium Priority Issues** | 2 |
| **Low Priority Issues** | 1 |
| **Positive Findings** | 12 |

### Status After Recent Fixes

The codebase improved significantly after fixing 17 GCP blocking calls in commit `72de053`. However, **3 blocking GCP API calls remain** that could cause 504 Gateway Timeouts under load.

---

## Critical Issues

### CRIT-001: GCP org_policy_scanner - Blocking recursive folder enumeration

**File:** `backend/app/scanners/gcp/org_policy_scanner.py`
**Lines:** 272-282
**Confidence:** 95%
**Category:** Async Patterns

**Description:**
The `_list_all_folders()` method contains a recursive `list_children()` function that calls `rm_client.list_folders()` DIRECTLY without using `run_sync()`. This is a synchronous GCP API call inside an async function that will BLOCK the event loop.

**Current Code:**
```python
async def list_children(parent: str) -> None:
    try:
        request = {"parent": parent}
        for folder in rm_client.list_folders(request=request):  # BLOCKS!
            all_folders.append(folder)
            await list_children(folder.name)
```

**Fix:**
```python
async def list_children(parent: str) -> None:
    try:
        request = {"parent": parent}

        # Use run_sync to avoid blocking the event loop
        def fetch_folders() -> list:
            folders = []
            for folder in rm_client.list_folders(request=request):
                folders.append(folder)
            return folders

        folders = await self.run_sync(fetch_folders)

        for folder in folders:
            all_folders.append(folder)
            await list_children(folder.name)
```

**Impact:** During large organisation scans with many nested folders, this could cause 504 Gateway Timeouts.

---

## High Priority Issues

### HIGH-001: EffectiveOrgPolicyScanner - Blocking get_effective_policy call

**File:** `backend/app/scanners/gcp/org_policy_scanner.py`
**Line:** ~475
**Confidence:** 90%
**Category:** Async Patterns

**Description:**
The `_get_effective_policy()` method calls `client.get_effective_policy()` directly without `run_sync()`.

**Fix:**
```python
# Use run_sync to avoid blocking
policy = await self.run_sync(
    client.get_effective_policy,
    request={"name": name}
)
```

---

### HIGH-002: SCCModuleStatusScanner - Blocking get_organization_settings call

**File:** `backend/app/scanners/gcp/scc_findings_scanner.py`
**Line:** ~338
**Confidence:** 90%
**Category:** Async Patterns

**Description:**
The `scan()` method calls `client.get_organization_settings()` directly without `run_sync()`.

**Fix:**
```python
org_settings = await self.run_sync(
    client.get_organization_settings,
    request={"name": org_settings_name}
)
```

---

## Medium Priority Issues

### MED-001: UK English inconsistency - 'organization' vs 'organisation'

**Category:** UK English
**Confidence:** 100%

**Description:**
The CLAUDE.md specifies UK English spelling ('organisation') but the codebase uses US spelling ('organization') extensively in:
- Database table names: `organizations`, `organization_members`
- Model/schema class names: `Organization`, `CloudOrganization`
- API endpoints: `/organizations`, `organization_id`

**Recommendation:**
Keep US spelling in code/DB/APIs (changing would be disruptive) but use UK spelling in:
- User-facing UI text
- Documentation/help text
- Email templates

---

### MED-002: Frontend uses US spelling for 'Organization'

**Category:** UK English
**Confidence:** 100%

**Description:**
Frontend TypeScript files use 'Organization' (US spelling) in component names, routes, and types.

**Recommendation:**
Keep type names/routes as `organization` (matches API) but use UK spelling in UI labels:
```tsx
<h1>Organisation Settings</h1>
<button>Create Organisation</button>
```

---

## Low Priority Issues

### LOW-001: Verify SecurityHub cache implementation skips API calls

**File:** `backend/app/scanners/aws/securityhub_scanner.py`
**Category:** Cache Performance
**Confidence:** 75%

**Description:**
The scanner imports cache functions but should be verified that cache hits actually SKIP the expensive AWS API calls, not just merge cached data.

**Expected Pattern:**
```python
cached = await get_cached_securityhub_controls(account_id)
if cached:
    return cached  # SKIP API call entirely!
response = await api_call()  # Only on cache miss
await cache_data(response)
return response
```

---

## Positive Findings

| Area | Finding |
|------|---------|
| **AWS Scanners** | All correctly use `run_sync()` for boto3 calls |
| **GCP Scanners** | 7 of 8 files use `run_sync()` correctly after fixes |
| **RBAC** | `require_role()` uses explicit role lists (no hierarchy assumption) |
| **Feature Gates** | Team invites correctly gated with `require_feature("team_invites")` |
| **Email Security** | Enumeration prevention with generic error messages |
| **Concurrency** | Row-level locking for ownership transfer |
| **Cache Security** | Sanitisation, size limits, and TTL enforcement |
| **Migration 048** | Follows FK constraint deletion order correctly |
| **Migration 049** | Idempotent with proper FK cascade on downgrade |
| **Credentials** | No hardcoded credentials (only test password hashes) |
| **Thread Pool** | All scanners inherit shared `BaseScanner` thread pool |
| **GBP Pricing** | All user-facing pricing uses £ symbols correctly |

---

## Files Requiring Attention

| Priority | File | Issue |
|----------|------|-------|
| Critical | `backend/app/scanners/gcp/org_policy_scanner.py` | Blocking `list_folders()` in recursive function |
| High | `backend/app/scanners/gcp/org_policy_scanner.py` | Blocking `get_effective_policy()` |
| High | `backend/app/scanners/gcp/scc_findings_scanner.py` | Blocking `get_organization_settings()` |

---

## Reference Implementations

### Correct Async Pattern (from org_log_sink_scanner.py:183-207)

```python
async def _list_all_folders(self, rm_client, org_id: str) -> list:
    all_folders = []

    async def list_children(parent: str) -> None:
        try:
            request = {"parent": parent}

            # Use run_sync to avoid blocking the event loop
            def fetch_folders() -> list:
                folders = []
                for folder in rm_client.list_folders(request=request):
                    folders.append(folder)
                return folders

            folders = await self.run_sync(fetch_folders)

            for folder in folders:
                all_folders.append(folder)
                await list_children(folder.name)
        except Exception as e:
            self.logger.warning("list_folders_failed", parent=parent, error=str(e))

    await list_children(f"organizations/{org_id}")
    return all_folders
```

---

## Recommendations

### Immediate (Priority 1)
1. Fix the 3 remaining GCP blocking calls listed above
2. These are trivial 5-10 line fixes each

### Short-term (Priority 2)
3. Document UK vs US English convention in CLAUDE.md
4. Verify SecurityHub cache actually skips API calls on hit

### Long-term (Priority 3)
5. Add integration tests that verify `run_sync()` is used for all cloud SDK calls
6. Consider a linter rule to catch direct cloud SDK calls without `run_sync()`
7. Add cache hit/miss logging to GCP scanners

---

## Test Suggestions

- [ ] Test GCP org scan with 100+ nested folders to verify no event loop blocking
- [ ] Test concurrent SecurityHub scans to verify cache hit skips API calls
- [ ] Test team invite flow with FREE tier user - verify 403 on POST /api/v1/teams/invites
- [ ] Test ownership transfer with simultaneous requests to verify row-level locking
- [ ] Load test: 10 concurrent scans to verify thread pool prevents blocking
- [ ] Test GCP EffectiveOrgPolicyScanner with 50+ constraints
- [ ] Verify cache expiry - scan twice within 5 minutes, verify second is faster

---

## Audit Methodology

This audit used the **A13E Profile** with the following weights:

| Category | Weight | Focus |
|----------|--------|-------|
| Async Patterns | 25% | boto3/GCP blocking calls, `run_sync()` usage |
| Security | 25% | RBAC, feature gates, credentials |
| UK English | 15% | Spelling, currency |
| Migrations | 15% | ENUM patterns, idempotency, FK order |
| Terraform | 10% | EventBridge DLQ/retry, CloudWatch alarms |
| Code Quality | 10% | Type hints, cache patterns, error handling |

---

*Report generated by Claude Code on 30 December 2025*
