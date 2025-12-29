# Type Hints Implementation Plan

## Overview

This plan addresses **309 untyped functions** across the codebase. Functions without return type annotations prevent mypy from checking their bodies, potentially hiding bugs.

## Current State

| Module | Untyped | Total Impact |
|--------|---------|--------------|
| app/api | 242 | Route handlers |
| app/data | 15 | Validation scripts |
| app/services | 11 | Business logic |
| app/cli | 11 | CLI tools |
| app/main.py | 8 | Entry point |
| app/core | 6 | Security code |
| app/scanners | 5 | Cloud integrations |
| app/mappers | 5 | ML/NLP utilities |
| app/scripts | 4 | One-off scripts |
| app/middleware | 1 | Request handling |
| app/validators | 1 | Validation logic |
| **TOTAL** | **309** | |

## Implementation Phases

### Phase 1: Security-Critical (P0) - 6 functions
**Files:**
- `app/core/billing_config.py` (4 functions)
- `app/core/database.py` (1 function)
- `app/core/rate_limiter.py` (1 function)

**Estimated effort:** 30 minutes

### Phase 2: Core Infrastructure (P1) - 20 functions
**Files:**
- `app/services/auth_service.py` (1 function)
- `app/services/aws_credential_service.py` (2 functions)
- `app/services/gcp_credential_service.py` (4 functions)
- `app/services/compliance_service.py` (1 function)
- `app/services/drift_detection_service.py` (1 function)
- `app/services/email_service.py` (1 function)
- `app/services/aws_org_discovery.py` (1 function)
- `app/main.py` (8 functions)
- `app/middleware/request_id.py` (1 function)

**Estimated effort:** 1-2 hours

### Phase 3: Cloud Integrations (P2) - 6 functions
**Files:**
- `app/scanners/aws/config_scanner.py` (2 functions)
- `app/scanners/aws/eventbridge_scanner.py` (1 function)
- `app/scanners/gcp/org_log_sink_scanner.py` (1 function)
- `app/scanners/gcp/org_policy_scanner.py` (1 function)
- `app/validators/base_validator.py` (1 function)

**Estimated effort:** 30 minutes

### Phase 4: API Routes (P3) - 242 functions
**Files:** 40+ route files in `app/api/`

This is the bulk of the work. FastAPI route handlers often have complex return types.

**Strategy:**
1. Most routes return Pydantic models - add `-> ModelName`
2. Some return `dict` - consider creating response models
3. DELETE endpoints return `-> None`
4. Dependency functions return their injected type

**Estimated effort:** 4-6 hours

### Phase 5: Utilities (P4-P5) - 35 functions
**Files:**
- `app/mappers/*.py` (5 functions)
- `app/data/remediation_templates/validation/*.py` (15 functions)
- `app/cli/*.py` (11 functions)
- `app/scripts/*.py` (4 functions)

**Estimated effort:** 1 hour

## mypy Configuration Changes

After adding type hints, update `mypy.ini`:

```ini
[mypy]
# Enable checking of untyped function bodies
check_untyped_defs = True

# Require all functions to have return type annotations
disallow_untyped_defs = True

# Require all functions to have argument type annotations
disallow_incomplete_defs = True

# Remove disabled error codes as they get fixed
disable_error_code = ...
```

## Gradual Rollout

To avoid breaking CI, enable strict checking per-module:

```ini
# Start with well-typed modules
[mypy-app.core.*]
check_untyped_defs = True
disallow_untyped_defs = True

[mypy-app.services.*]
check_untyped_defs = True
disallow_untyped_defs = True

# Add more modules as they're typed
```

## Common Type Patterns

### FastAPI Route Handlers
```python
# Before
@router.get("/items")
async def list_items(db: AsyncSession = Depends(get_db)):
    ...

# After
@router.get("/items")
async def list_items(db: AsyncSession = Depends(get_db)) -> ItemListResponse:
    ...
```

### Service Methods
```python
# Before
async def get_user(self, user_id: UUID):
    ...

# After
async def get_user(self, user_id: UUID) -> Optional[User]:
    ...
```

### Callbacks/Lambdas (use Callable)
```python
from typing import Callable, Awaitable

def rate_limit(key_func: Callable[[Request], Awaitable[str]]) -> ...:
    ...
```

## Verification

After each phase:
1. Run `mypy app/` to check for errors
2. Run tests to ensure no regressions
3. Commit and push

## Timeline

| Phase | Effort | Priority |
|-------|--------|----------|
| Phase 1 | 30 min | Critical |
| Phase 2 | 1-2 hrs | High |
| Phase 3 | 30 min | Medium |
| Phase 4 | 4-6 hrs | Normal |
| Phase 5 | 1 hr | Low |
| **Total** | **7-10 hrs** | |
