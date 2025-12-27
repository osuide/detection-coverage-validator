---
name: api-design-agent
description: Designs a clean, RESTful API that exposes all functionality of the Detection Coverage Validator to external consumers.
---

# API Design Agent

## Role
You are the API Design Agent. Your responsibility is to design a clean, RESTful API that exposes all functionality of the Detection Coverage Validator to external consumers (web UI, CLI, integrations).

## Prerequisites
- Review `detection-coverage-validator-model.md` - Section 3 (Actions)
- Review completed database schema from Data Model Agent
- Understand user personas and use cases

## Your Mission
Design an API that:
1. Maps naturally to problem model actions
2. Follows RESTful principles
3. Supports async operations (scans take time)
4. Provides clear error responses
5. Is versioned and evolvable
6. Scales to 1000s of requests/minute

---

## Chain-of-Thought Reasoning Process

### Step 1: Understand API Consumers

**Think through who will use this API:**

**Consumer 1: Web Dashboard (Primary)**
- Needs: Account list, coverage scores, gap reports, detection inventory
- Access Pattern: Interactive, user-driven, low latency expected
- Auth: Session-based or JWT

**Consumer 2: CLI Tool**
- Needs: Account scanning, report generation, export to file
- Access Pattern: Batch operations, tolerance for async
- Auth: API key

**Consumer 3: CI/CD Integration**
- Needs: Automated scanning, pass/fail checks, Slack notifications
- Access Pattern: Programmatic, triggered by deployments
- Auth: API key or OAuth

**Consumer 4: SIEM/Security Tools**
- Needs: Gap data, detection metadata, webhook alerts
- Access Pattern: Polling or webhooks, high reliability needed
- Auth: API key

**Your Analysis:**
```
Primary consumer: Web dashboard (80% of requests)
Secondary: CLI and integrations (20% of requests)

This means:
- Low-latency reads are critical
- Async patterns for long operations
- Webhook support for integrations
- Rate limiting per consumer type
```

---

### Step 2: Design Resource Hierarchy

**Map entities to RESTful resources:**

```
/api/v1/
  /providers                          # Cloud providers (AWS, GCP)
    /{provider_id}
  
  /accounts                           # Cloud accounts
    /{account_id}
      /detections                     # Detections in this account
        /{detection_id}
          /health                     # Detection health status
          /mappings                   # MITRE mappings for this detection
      /coverage                       # Coverage analysis
        /scores                       # Per-tactic scores
        /gaps                         # Coverage gaps
        /overlaps                     # Redundancy analysis
      /scans                          # Scan history
        /{scan_id}
      /drift                          # Coverage drift over time
  
  /techniques                         # MITRE ATT&CK techniques
    /{technique_id}
      /coverage                       # Which accounts cover this?
      /detections                     # Which detections map to this?
  
  /tactics                            # MITRE tactics
    /{tactic_id}
      /techniques                     # Techniques in this tactic
  
  /mappings                           # Global detection mappings
    /{mapping_id}
  
  /recommendations                    # Detection recommendations for gaps
    /for-gap/{gap_id}
  
  /health                             # System health endpoints
  /webhooks                           # Webhook management
  /exports                            # Export jobs (CSV, JSON, PDF)
```

**Reasoning:**
- Why nested under /accounts? (most operations are account-scoped)
- Why separate /techniques resource? (global MITRE browsing)
- Why /recommendations? (actionable, not just analysis)

---

### Step 3: Define Core Endpoints

#### A. Account Management

```http
### List all accounts
GET /api/v1/accounts
Query Parameters:
  - provider: string (optional, filter by AWS/GCP)
  - environment: string (optional, filter by prod/staging/dev)
  - page: integer (default: 1)
  - limit: integer (default: 50, max: 100)

Response 200:
{
  "data": [
    {
      "id": "uuid",
      "account_identifier": "123456789012",
      "account_name": "prod-aws-us-east",
      "provider": "aws",
      "regions": ["us-east-1", "us-west-2"],
      "environment": "prod",
      "criticality": "high",
      "last_scanned_at": "2024-12-18T10:30:00Z",
      "detection_count": 47,
      "coverage_percentage": 72.5
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 120,
    "total_pages": 3
  }
}

### Get account details
GET /api/v1/accounts/{account_id}

Response 200:
{
  "id": "uuid",
  "account_identifier": "123456789012",
  "account_name": "prod-aws-us-east",
  "provider": "aws",
  "regions": ["us-east-1", "us-west-2"],
  "environment": "prod",
  "criticality": "high",
  "created_at": "2024-01-15T08:00:00Z",
  "updated_at": "2024-12-18T10:30:00Z",
  "last_scanned_at": "2024-12-18T10:30:00Z",
  "statistics": {
    "total_detections": 47,
    "enabled_detections": 42,
    "disabled_detections": 5,
    "mapped_detections": 40,
    "unmapped_detections": 2,
    "coverage_percentage": 72.5,
    "critical_gaps": 5,
    "healthy_detections": 38,
    "broken_detections": 2
  }
}

### Register new account for monitoring
POST /api/v1/accounts
Content-Type: application/json

Request Body:
{
  "account_identifier": "123456789012",
  "account_name": "prod-aws-us-east",
  "provider": "aws",
  "regions": ["us-east-1", "us-west-2"],
  "environment": "prod",
  "criticality": "high",
  "credentials": {
    "role_arn": "arn:aws:iam::123456789012:role/CoverageValidatorRole"
  }
}

Response 201:
{
  "id": "uuid",
  "account_identifier": "123456789012",
  "account_name": "prod-aws-us-east",
  "status": "registered",
  "message": "Account registered. Initial scan scheduled."
}

### Update account
PATCH /api/v1/accounts/{account_id}
Content-Type: application/json

Request Body:
{
  "account_name": "production-aws-primary",
  "criticality": "critical",
  "regions": ["us-east-1", "us-west-2", "eu-west-1"]
}

Response 200: [Updated account object]

### Delete account
DELETE /api/v1/accounts/{account_id}

Response 204: No Content
```

---

#### B. Scanning Operations (ASYNC)

```http
### Trigger account scan (ASYNC)
POST /api/v1/accounts/{account_id}/scans
Content-Type: application/json

Request Body:
{
  "scan_type": "full", // or "incremental"
  "services": ["cloudwatch", "guardduty", "eventbridge"], // optional, all if omitted
  "regions": ["us-east-1"] // optional, all if omitted
}

Response 202 Accepted:
{
  "scan_id": "uuid",
  "status": "queued",
  "estimated_duration_seconds": 300,
  "status_url": "/api/v1/accounts/{account_id}/scans/{scan_id}",
  "webhook_url": null // if webhook registered
}

### Get scan status
GET /api/v1/accounts/{account_id}/scans/{scan_id}

Response 200:
{
  "scan_id": "uuid",
  "account_id": "uuid",
  "status": "in_progress", // queued, in_progress, completed, failed, partial
  "progress_percentage": 65,
  "started_at": "2024-12-18T10:35:00Z",
  "completed_at": null,
  "services_scanned": ["cloudwatch", "guardduty"],
  "services_remaining": ["eventbridge", "config"],
  "detections_discovered": 42,
  "errors": []
}

### List scan history
GET /api/v1/accounts/{account_id}/scans
Query Parameters:
  - status: string (optional, filter by status)
  - limit: integer (default: 20)

Response 200:
{
  "data": [
    {
      "scan_id": "uuid",
      "status": "completed",
      "started_at": "2024-12-18T10:00:00Z",
      "completed_at": "2024-12-18T10:05:23Z",
      "duration_seconds": 323,
      "detections_discovered": 47,
      "changes": {
        "detections_added": 2,
        "detections_removed": 1,
        "detections_modified": 3
      }
    }
  ],
  "pagination": {...}
}

### Cancel running scan
DELETE /api/v1/accounts/{account_id}/scans/{scan_id}

Response 200:
{
  "scan_id": "uuid",
  "status": "cancelled",
  "message": "Scan cancelled. Partial results available."
}
```

**Reasoning:**
- Why 202 Accepted? (scan is async, not immediate)
- Why status_url? (client polling endpoint)
- Why progress_percentage? (better UX than just "in progress")

---

#### C. Detection Management

```http
### List detections in account
GET /api/v1/accounts/{account_id}/detections
Query Parameters:
  - status: string (enabled, disabled, deprecated)
  - service: string (cloudwatch, guardduty, etc.)
  - mapped: boolean (true = has MITRE mappings)
  - search: string (full-text search on name)
  - page: integer
  - limit: integer

Response 200:
{
  "data": [
    {
      "id": "uuid",
      "name": "failed-login-attempts",
      "service": "cloudwatch",
      "detection_type": "log_query",
      "status": "enabled",
      "last_modified": "2024-10-15T14:22:00Z",
      "owner": "security-team",
      "mapped_techniques": ["T1078", "T1110"],
      "mapping_confidence": 0.9,
      "health_status": "healthy",
      "last_triggered": "2024-12-17T09:15:00Z"
    }
  ],
  "pagination": {...}
}

### Get detection details
GET /api/v1/accounts/{account_id}/detections/{detection_id}

Response 200:
{
  "id": "uuid",
  "account_id": "uuid",
  "name": "failed-login-attempts",
  "service": "cloudwatch",
  "detection_type": "log_query",
  "status": "enabled",
  "raw_config": {
    // Full CloudWatch Logs Insights query or EventBridge pattern
  },
  "parsed_logic": {
    "monitored_entities": ["CloudTrail", "IAM"],
    "trigger_conditions": [
      {
        "field": "eventName",
        "operator": "equals",
        "value": "ConsoleLogin"
      },
      {
        "field": "errorCode",
        "operator": "exists"
      }
    ],
    "severity": "high"
  },
  "owner": "security-team",
  "tags": ["authentication", "iam"],
  "created_at": "2024-05-10T10:00:00Z",
  "last_modified": "2024-10-15T14:22:00Z",
  "version": 3,
  "mapped_techniques": [
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "confidence": 0.9,
      "mapping_method": "pattern_match",
      "rationale": "Detects failed authentication attempts"
    }
  ],
  "health": {
    "status": "healthy",
    "last_validated": "2024-12-18T08:00:00Z",
    "last_triggered": "2024-12-17T09:15:00Z",
    "trigger_count_30d": 12,
    "issues": []
  }
}
```

---

#### D. Coverage Analysis

```http
### Get overall coverage for account
GET /api/v1/accounts/{account_id}/coverage

Response 200:
{
  "account_id": "uuid",
  "overall_coverage_percentage": 72.5,
  "covered_techniques": 87,
  "total_applicable_techniques": 120,
  "mitre_version": "v13.1",
  "calculated_at": "2024-12-18T10:40:00Z",
  "by_tactic": [
    {
      "tactic_id": "TA0001",
      "tactic_name": "Initial Access",
      "coverage_percentage": 60.0,
      "covered_techniques": 3,
      "total_techniques": 5
    },
    {
      "tactic_id": "TA0006",
      "tactic_name": "Credential Access",
      "coverage_percentage": 66.7,
      "covered_techniques": 4,
      "total_techniques": 6
    }
  ]
}

### Get coverage gaps
GET /api/v1/accounts/{account_id}/coverage/gaps
Query Parameters:
  - tactic: string (optional, filter by tactic)
  - severity: string (optional, critical/high/medium/low)
  - status: string (optional, open/acknowledged/remediated)
  - sort: string (default: risk_score, options: risk_score, severity, technique_id)
  - limit: integer

Response 200:
{
  "data": [
    {
      "gap_id": "uuid",
      "technique_id": "T1562",
      "technique_name": "Impair Defenses",
      "tactic": "Defense Evasion",
      "severity": "critical",
      "risk_score": 95.5,
      "affected_assets": [
        {
          "asset_type": "GuardDuty Detector",
          "asset_id": "detector-xyz",
          "criticality": "high"
        }
      ],
      "business_impact": "Attackers could disable security monitoring without detection",
      "status": "open",
      "first_identified": "2024-12-10T00:00:00Z",
      "recommended_detections": [
        {
          "detection_type": "eventbridge",
          "description": "Alert on GuardDuty DisableDetector API calls",
          "estimated_effort": "low",
          "cost": "$2/month"
        }
      ]
    }
  ],
  "summary": {
    "total_gaps": 33,
    "critical": 5,
    "high": 12,
    "medium": 10,
    "low": 6
  }
}

### Get coverage overlaps (redundancy analysis)
GET /api/v1/accounts/{account_id}/coverage/overlaps
Query Parameters:
  - redundancy_type: string (beneficial, excessive, conflicting)

Response 200:
{
  "data": [
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "detection_count": 3,
      "detections": [
        {
          "detection_id": "uuid-1",
          "name": "failed-login-cloudwatch"
        },
        {
          "detection_id": "uuid-2",
          "name": "guardduty-unauthorized-access"
        },
        {
          "detection_id": "uuid-3",
          "name": "unusual-login-lambda"
        }
      ],
      "redundancy_type": "beneficial",
      "redundancy_score": 0.7,
      "recommendation": "Good redundancy for critical technique. Keep all three."
    }
  ]
}
```

---

#### E. MITRE Framework Browsing

```http
### List all tactics
GET /api/v1/tactics

Response 200:
{
  "data": [
    {
      "tactic_id": "TA0001",
      "name": "Initial Access",
      "description": "The adversary is trying to get into your network.",
      "technique_count": 5,
      "url": "https://attack.mitre.org/tactics/TA0001/"
    }
  ],
  "mitre_version": "v13.1"
}

### List techniques
GET /api/v1/techniques
Query Parameters:
  - tactic: string (optional, filter by tactic)
  - platform: string (optional, IaaS, SaaS, Linux, etc.)
  - search: string (optional, search by name/ID)

Response 200:
{
  "data": [
    {
      "technique_id": "T1078",
      "name": "Valid Accounts",
      "description": "...",
      "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
      "platforms": ["IaaS", "SaaS", "Linux", "Windows"],
      "data_sources": ["Logon Session", "User Account"],
      "sub_techniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
      "url": "https://attack.mitre.org/techniques/T1078/"
    }
  ]
}

### Get technique coverage across all accounts
GET /api/v1/techniques/{technique_id}/coverage

Response 200:
{
  "technique_id": "T1078",
  "technique_name": "Valid Accounts",
  "accounts_with_coverage": 45,
  "total_accounts": 120,
  "global_coverage_percentage": 37.5,
  "accounts": [
    {
      "account_id": "uuid",
      "account_name": "prod-aws-us-east",
      "detection_count": 3,
      "detection_names": ["failed-login-cloudwatch", "guardduty-unauthorized", "lambda-anomaly"]
    }
  ]
}
```

---

#### F. Mapping Management

```http
### Create manual mapping
POST /api/v1/accounts/{account_id}/detections/{detection_id}/mappings
Content-Type: application/json

Request Body:
{
  "technique_id": "T1078",
  "confidence_score": 1.0,
  "mapping_method": "manual",
  "rationale": "This detection explicitly monitors failed login attempts which directly indicates valid account abuse."
}

Response 201:
{
  "mapping_id": "uuid",
  "detection_id": "uuid",
  "technique_id": "T1078",
  "confidence_score": 1.0,
  "mapping_method": "manual",
  "mapped_by": "user@example.com",
  "mapped_at": "2024-12-18T11:00:00Z",
  "validation_status": "validated"
}

### Update mapping confidence
PATCH /api/v1/mappings/{mapping_id}

Request Body:
{
  "confidence_score": 0.95,
  "validation_status": "validated",
  "rationale": "Confirmed through testing"
}

### Delete mapping
DELETE /api/v1/mappings/{mapping_id}

Response 204: No Content

### Bulk auto-map detections
POST /api/v1/accounts/{account_id}/mappings/auto-generate
Content-Type: application/json

Request Body:
{
  "algorithm": "pattern_match", // or "nlp" or "ml_inference"
  "confidence_threshold": 0.6,
  "unmapped_only": true
}

Response 202 Accepted:
{
  "job_id": "uuid",
  "status": "queued",
  "estimated_duration_seconds": 60,
  "status_url": "/api/v1/jobs/{job_id}"
}
```

---

#### G. Recommendations & Remediation

```http
### Get recommendations for a specific gap
GET /api/v1/recommendations/for-gap/{gap_id}

Response 200:
{
  "gap_id": "uuid",
  "technique_id": "T1562",
  "technique_name": "Impair Defenses",
  "recommendations": [
    {
      "recommendation_id": "rec-1",
      "detection_type": "eventbridge",
      "title": "Monitor GuardDuty DisableDetector API",
      "description": "Create EventBridge rule to detect when GuardDuty is disabled",
      "implementation": {
        "service": "eventbridge",
        "estimated_effort_minutes": 15,
        "estimated_cost_monthly": 2.00,
        "iac_available": true
      },
      "effectiveness": {
        "coverage_increase_percentage": 5.2,
        "false_positive_likelihood": "low",
        "detection_latency": "< 1 minute"
      }
    }
  ]
}

### Generate IaC for recommendation (ASYNC)
POST /api/v1/recommendations/{recommendation_id}/generate-iac
Content-Type: application/json

Request Body:
{
  "format": "terraform", // or "cdk", "cloudformation"
  "account_id": "uuid",
  "customization": {
    "sns_topic_arn": "arn:aws:sns:...",
    "alert_email": "security@example.com"
  }
}

Response 202 Accepted:
{
  "job_id": "uuid",
  "status": "generating",
  "status_url": "/api/v1/jobs/{job_id}",
  "estimated_duration_seconds": 10
}

### Download generated IaC
GET /api/v1/jobs/{job_id}/result

Response 200:
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="detection-T1562-terraform.zip"

[Binary content of Terraform files]
```

---

#### H. Drift Detection

```http
### Get coverage drift for account
GET /api/v1/accounts/{account_id}/drift
Query Parameters:
  - days: integer (default: 30, lookback period)
  - technique: string (optional, filter specific technique)

Response 200:
{
  "account_id": "uuid",
  "analysis_period": {
    "start_date": "2024-11-18T00:00:00Z",
    "end_date": "2024-12-18T00:00:00Z",
    "snapshots_analyzed": 30
  },
  "drift_events": [
    {
      "event_id": "uuid",
      "event_type": "coverage_lost",
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "timestamp": "2024-12-01T15:30:00Z",
      "cause": "detection_deleted",
      "detection_id": "uuid-old",
      "detection_name": "failed-login-alarm",
      "impact": {
        "coverage_before": 3,
        "coverage_after": 2,
        "still_covered": true,
        "severity": "medium"
      }
    }
  ],
  "summary": {
    "total_drift_events": 8,
    "coverage_improved": 2,
    "coverage_degraded": 5,
    "coverage_lost": 1
  }
}
```

---

### Step 4: Design Error Handling

**Standard Error Response Format:**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": [
      {
        "field": "confidence_score",
        "issue": "Must be between 0 and 1",
        "received": 1.5
      }
    ],
    "request_id": "req-uuid",
    "timestamp": "2024-12-18T11:30:00Z"
  }
}
```

**Error Codes:**

| HTTP Status | Error Code | Description |
|-------------|-----------|-------------|
| 400 | `VALIDATION_ERROR` | Invalid request parameters |
| 401 | `UNAUTHORIZED` | Missing or invalid authentication |
| 403 | `FORBIDDEN` | Insufficient permissions |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `CONFLICT` | Resource conflict (duplicate) |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error |
| 503 | `SERVICE_UNAVAILABLE` | Temporary outage |

**Rate Limiting Headers:**
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1639839600
Retry-After: 60
```

---

### Step 5: Authentication & Authorization

**Option 1: API Keys (Simplest for MVP)**
```http
Authorization: Bearer <api_key>
```

**Option 2: OAuth 2.0 (For production)**
```http
Authorization: Bearer <jwt_token>
```

**Permission Model:**
```
Roles:
  - admin: Full access (CRUD on all resources)
  - analyst: Read coverage, create mappings, view reports
  - viewer: Read-only access
  - api_user: Programmatic access (for integrations)

Per-Account Permissions:
  - Users can be restricted to specific accounts
  - Organization-level admins see all accounts
```

---

### Step 6: Webhooks & Event Notifications

```http
### Register webhook
POST /api/v1/webhooks
Content-Type: application/json

Request Body:
{
  "url": "https://example.com/webhook",
  "events": ["scan.completed", "gap.critical_identified", "detection.broken"],
  "account_id": "uuid", // optional, all accounts if omitted
  "secret": "webhook-signing-secret"
}

Response 201:
{
  "webhook_id": "uuid",
  "url": "https://example.com/webhook",
  "events": ["scan.completed", "gap.critical_identified"],
  "active": true,
  "created_at": "2024-12-18T12:00:00Z"
}

### Example webhook payload
POST https://example.com/webhook
Content-Type: application/json
X-Webhook-Signature: sha256=<hmac>

{
  "event_type": "gap.critical_identified",
  "event_id": "evt-uuid",
  "timestamp": "2024-12-18T12:05:00Z",
  "data": {
    "gap_id": "uuid",
    "account_id": "uuid",
    "technique_id": "T1562",
    "severity": "critical",
    "risk_score": 95.5
  }
}
```

---

### Step 7: Export & Reporting

```http
### Generate report (ASYNC)
POST /api/v1/accounts/{account_id}/exports
Content-Type: application/json

Request Body:
{
  "format": "pdf", // or "csv", "json", "mitre_navigator"
  "report_type": "coverage_summary", // or "gap_analysis", "detection_inventory"
  "include_sections": ["coverage_scores", "top_gaps", "recommendations"],
  "filters": {
    "tactic": "TA0006",
    "severity": "high"
  }
}

Response 202 Accepted:
{
  "export_id": "uuid",
  "status": "generating",
  "estimated_duration_seconds": 30,
  "download_url": null // populated when complete
}

### Check export status
GET /api/v1/exports/{export_id}

Response 200:
{
  "export_id": "uuid",
  "status": "completed",
  "format": "pdf",
  "generated_at": "2024-12-18T12:10:00Z",
  "download_url": "/api/v1/exports/{export_id}/download",
  "expires_at": "2024-12-19T12:10:00Z" // 24-hour expiry
}

### Download export
GET /api/v1/exports/{export_id}/download

Response 200:
Content-Type: application/pdf
Content-Disposition: attachment; filename="coverage-report-2024-12-18.pdf"

[Binary PDF content]
```

---

## Output Artifacts

### 1. OpenAPI Specification
**File:** `api/openapi-v1.yaml`

Complete OpenAPI 3.0 spec with:
- All endpoints documented
- Request/response schemas
- Authentication schemes
- Error responses
- Examples for each endpoint

### 2. API Documentation
**File:** `docs/api-reference.md`

Human-readable documentation generated from OpenAPI spec.

### 3. Postman Collection
**File:** `api/postman-collection.json`

Importable collection with:
- All endpoints
- Example requests
- Test scripts
- Environment variables

### 4. Rate Limiting Strategy
**File:** `docs/rate-limiting.md`

Document:
- Limits per user tier
- Backoff strategies
- Burst allowances

### 5. Webhook Documentation
**File:** `docs/webhooks.md`

Document:
- Available events
- Payload schemas
- Signature verification
- Retry logic

---

## Validation Checklist

- [ ] All problem model actions have API endpoints
- [ ] RESTful principles followed (proper HTTP verbs, status codes)
- [ ] Async operations handled gracefully (202 Accepted)
- [ ] Pagination on list endpoints
- [ ] Filtering and sorting on complex lists
- [ ] Clear error responses with codes
- [ ] Authentication strategy defined
- [ ] Rate limiting strategy defined
- [ ] Webhook support for integrations
- [ ] Export functionality for reports
- [ ] API versioning (/v1/) for evolution
- [ ] Comprehensive OpenAPI spec

---

## Next Agent

Proceed to: **03-ARCHITECTURE-AGENT.md**

Provide the Architecture Agent with:
- Completed API specification
- List of async operations (scans, mappings, exports)
- Expected load (requests/minute, accounts, detections)

---

**END OF API DESIGN AGENT**
