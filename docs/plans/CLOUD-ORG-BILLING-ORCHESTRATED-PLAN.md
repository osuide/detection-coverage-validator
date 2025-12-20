# Cloud Organisation & Billing - Orchestrated Implementation Plan

## Master Orchestrator Context

**Reference Documents:**
- `detection-coverage-validator-model.md` - Formal problem model
- `CLOUD-ORG-AND-BILLING-IMPLEMENTATION-PLAN.md` - Feature specification
- `00-MASTER-ORCHESTRATOR.md` - Orchestration methodology

**Estimated Duration:** 12-18 weeks
**Status:** Planning

---

## Chain-of-Thought Process

### Phase 1: Billing Model Update (Foundation)

**Before proceeding, reason through:**
- What billing entities need to change in the data model?
- How do the new tiers (Free, Individual, Pro, Enterprise) map to existing `AccountTier` enum?
- What feature gates need to be enforced at the API layer?
- How do we handle existing subscriber migration without service disruption?
- What Stripe products/prices need updating?

**Agent Invocation:** `01-DATA-MODEL-AGENT.md` (billing subset)

**Validation Criteria:**
- [ ] `AccountTier` enum includes new values: `FREE`, `INDIVIDUAL`, `PRO`, `ENTERPRISE`
- [ ] `billing_config.py` defines tier limits: max_accounts, max_team_members, features
- [ ] `Subscription` model tracks: `org_features_enabled`, `history_retention_days`
- [ ] Feature gate dependency `require_org_features` created
- [ ] Stripe products align with new tier pricing ($0, $29, $250, custom)
- [ ] Migration path defined for existing `subscriber` tier customers

**Critical Decisions:**

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| Tier enforcement | Backend-enforced | UI can be bypassed; enforce at API layer |
| Account counting | Active accounts only | Don't count disconnected accounts |
| Grace period | 3 months | Existing 7-27 account customers get time to adjust |
| Stripe products | Create new, don't modify | Clean separation; old products for legacy |

**Output Artefacts:**
- `backend/app/core/billing_config.py`
- Migration: `add_billing_tier_enhancements.py`
- Updated `backend/app/api/v1/endpoints/billing.py`

**Dependencies:** None (foundation phase)

---

### Phase 2: Cloud Organisation Data Model

**Before proceeding, reason through:**
- How do AWS Organisations and GCP Organisations differ structurally?
- What hierarchy metadata needs persisting (OUs, Folders)?
- How should `CloudOrganization` relate to existing `Organization` (our tenant)?
- How do org-level detections differ from account-level detections?
- What's the lifecycle: discovered → connecting → connected → partial → error?

**Agent Invocation:** `01-DATA-MODEL-AGENT.md` (organisation entities)

**Validation Criteria:**
- [ ] `CloudOrganization` model supports both AWS and GCP providers
- [ ] `CloudOrganizationMember` tracks discovered accounts/projects before connection
- [ ] `hierarchy_path` enables OU/Folder filtering queries
- [ ] `CloudAccount.cloud_organization_id` links accounts to their org
- [ ] `Detection.detection_scope` distinguishes account vs organisation level
- [ ] `Detection.applies_to_all_accounts` / `applies_to_account_ids` handles org-level scope
- [ ] `CoverageSnapshot` tracks `org_detection_count`, `org_covered_techniques`

**Critical Decisions:**

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| Org member as separate table | Yes | Tracks discovery state before CloudAccount creation |
| Hierarchy storage | Materialised path | Fast queries, readable, works for both providers |
| Detection scope constraint | CHECK constraint | Database-level enforcement of scope rules |
| Nullable cloud_account_id | Yes | Org-level detections don't belong to specific account |

**Output Artefacts:**
- `backend/app/models/cloud_organization.py`
- Migrations: `create_cloud_organizations.py`, `modify_detections_for_org.py`
- Pydantic schemas: `CloudOrganizationCreate`, `CloudOrganizationResponse`

**Dependencies:** Phase 1 (billing tier gates org features)

---

### Phase 3: AWS Organisation Integration

**Before proceeding, reason through:**
- What AWS APIs are needed? (`organizations:Describe*`, `organizations:List*`)
- How do we discover delegated admins for GuardDuty/Security Hub?
- What org-level detection sources exist? (Org CloudTrail, Config Aggregator, Security Hub Aggregator)
- How do SCPs factor into detection coverage (preventive controls)?
- What credentials are needed? (Management account or delegated admin)

**Agent Invocation:** `04-PARSER-AGENT.md` (AWS org scanners)

**Validation Criteria:**
- [ ] `AWSOrganizationDiscoveryService` lists all accounts via `ListAccounts`
- [ ] OU hierarchy built via `ListOrganizationalUnitsForParent`
- [ ] Delegated admins discovered via `ListDelegatedAdministrators`
- [ ] `OrganizationCloudTrailScanner` detects org-level trails
- [ ] `DelegatedGuardDutyScanner` scans from delegated admin account
- [ ] `SecurityHubAggregatorScanner` finds cross-account aggregation
- [ ] `ConfigAggregatorScanner` detects multi-account/region aggregators
- [ ] Org detections stored with `detection_scope='organization'`

**Critical Decisions:**

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| Credential approach | Cross-account role | Management account assumes role into members |
| Scan parallelisation | Per-account parallel, per-service sequential | Respects rate limits |
| SCP handling | Tag as preventive control | Not a detection, but affects coverage posture |
| Auto-connect members | Opt-in | User chooses which accounts to connect |

**Required IAM Permissions (read-only):**
```json
{
  "Effect": "Allow",
  "Action": [
    "organizations:Describe*",
    "organizations:List*",
    "guardduty:ListDetectors",
    "guardduty:ListMembers",
    "securityhub:GetAdministratorAccount",
    "securityhub:ListMembers",
    "config:DescribeConfigurationAggregators"
  ],
  "Resource": "*"
}
```

**Output Artefacts:**
- `backend/app/services/aws_org_discovery.py`
- `backend/app/scanners/org_cloudtrail_scanner.py`
- `backend/app/scanners/delegated_guardduty_scanner.py`
- `backend/app/scanners/config_aggregator_scanner.py`

**Dependencies:** Phase 2 (data model exists)

---

### Phase 4: GCP Organisation Integration

**Before proceeding, reason through:**
- What GCP APIs are needed? (Cloud Resource Manager, Cloud Asset Inventory)
- How does folder hierarchy differ from AWS OUs?
- What org-level detection sources exist? (Org log sinks, SCC, Asset Inventory)
- How do organisation policies factor in?
- What service account permissions are needed?

**Agent Invocation:** `04-PARSER-AGENT.md` (GCP org scanners)

**Validation Criteria:**
- [ ] `GCPOrganizationDiscoveryService` lists all projects via Resource Manager
- [ ] Folder hierarchy built via `folders.list` / `projects.list`
- [ ] Org-level log sinks discovered via `organizations.sinks.list`
- [ ] Security Command Center findings retrieved at org level
- [ ] Organisation policies discovered via `organizations.getOrgPolicy`
- [ ] Folder-level sinks and policies supported
- [ ] GCP org detections stored with correct scope

**Critical Decisions:**

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| Auth approach | Organisation-level service account | Single credential for entire org |
| SCC integration | Premium features only | Standard tier has limited detections |
| Folder vs org sinks | Both supported | Folder sinks may cover subset of projects |
| Project states | Filter ACTIVE only | Ignore DELETE_REQUESTED, etc. |

**Required GCP Permissions:**
```yaml
- resourcemanager.organizations.get
- resourcemanager.folders.list
- resourcemanager.projects.list
- logging.sinks.list
- securitycenter.sources.list
- cloudasset.assets.searchAllResources
```

**Output Artefacts:**
- `backend/app/services/gcp_org_discovery.py`
- `backend/app/scanners/gcp_org_log_sink_scanner.py`
- Enhanced `backend/app/scanners/security_command_center_scanner.py`
- `backend/app/scanners/gcp_org_policy_scanner.py`

**Dependencies:** Phase 2 (can run parallel to Phase 3)

---

### Phase 5: Coverage Calculation Updates

**Before proceeding, reason through:**
- How do org-level detections contribute to account coverage?
- What's the inheritance model? (org detections apply to all or subset of accounts)
- How do we avoid double-counting when detection covers multiple accounts?
- What visualisation best shows org vs account contribution?
- How do we calculate aggregate org-wide coverage?

**Agent Invocation:** `06-ANALYSIS-AGENT.md`

**Validation Criteria:**
- [ ] `calculate_account_coverage_with_org()` includes inherited org detections
- [ ] Coverage breakdown shows: account_techniques, org_techniques, overlap_techniques
- [ ] `calculate_org_coverage()` aggregates across all member accounts
- [ ] Minimum coverage view: technique covered only if ALL accounts have it
- [ ] Any coverage view: technique covered if ANY account has it
- [ ] `CoverageSnapshot.coverage_breakdown` stores contribution details
- [ ] API returns enhanced coverage data with org context

**Critical Decisions:**

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| Org detection inheritance | Configurable per detection | Some apply to all, some to subset |
| Aggregate coverage method | Both min and union available | Different use cases |
| Overlap handling | Track but don't deduplicate | Redundancy is good for coverage |
| Default view | Per-account with org contribution | Most actionable |

**Coverage Calculation Formula:**
```python
def calculate_account_coverage_with_org(account_id, org_id):
    account_detections = get_detections(account_id=account_id)
    org_detections = get_org_detections_for_account(org_id, account_id)

    all_detections = account_detections + org_detections
    covered_techniques = {d.technique_id for d in all_detections if d.confidence >= 0.6}

    return {
        "total_coverage": len(covered_techniques) / TOTAL_TECHNIQUES,
        "account_contribution": len(account_only_techniques),
        "org_contribution": len(org_only_techniques),
        "overlap": len(both_techniques)
    }
```

**Output Artefacts:**
- Updated `backend/app/services/coverage_calculator.py`
- New endpoint: `GET /api/v1/coverage/organization/{org_id}`
- New endpoint: `GET /api/v1/coverage/organization/{org_id}/breakdown`
- Enhanced `CoverageSnapshot` creation

**Dependencies:** Phases 3 & 4 (org detections exist)

---

### Phase 6: Frontend Organisation UX

**Before proceeding, reason through:**
- What's the connection flow for AWS vs GCP orgs?
- How do we display hierarchy (tree view)?
- What org-level dashboard metrics are valuable?
- How do we show org vs account detection contribution?
- What billing upgrade prompts are needed for Individual tier users?

**Agent Invocation:** `07-UI-DESIGN-AGENT.md`

**Validation Criteria:**
- [ ] `ConnectOrganization` page with provider selection (AWS/GCP)
- [ ] Credential input step with clear permission requirements
- [ ] Discovery results showing account tree with hierarchy
- [ ] Account selection tree with bulk select/deselect
- [ ] `OrganizationDashboard` with aggregate coverage gauge
- [ ] Per-account coverage breakdown table
- [ ] Org-level detections list with scope indicators
- [ ] Sidebar navigation includes "Organisations" section
- [ ] Pro tier upgrade prompt for Individual tier users

**Critical Decisions:**

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| Connection wizard | Multi-step | Complex process, guide user through |
| Hierarchy display | Collapsible tree | Handles large orgs, shows structure |
| Default account selection | All active accounts | User can deselect; opt-out easier |
| Coverage visualisation | Stacked bar chart | Shows account vs org contribution |

**User Flows:**

```
1. Connect AWS Organisation
   └─> Select AWS provider
   └─> Enter management account credentials
   └─> Discover organisation
   └─> Review member accounts
   └─> Select accounts to connect
   └─> Deploy cross-account role (CFN template provided)
   └─> Confirm & start scanning

2. View Org Dashboard
   └─> See aggregate coverage gauge
   └─> See per-account coverage table
   └─> Filter by OU/Folder
   └─> Drill into specific account
   └─> View org-level detections

3. Upgrade to Pro (from Individual)
   └─> Click "Connect Organisation"
   └─> See upgrade prompt
   └─> Review Pro features
   └─> Confirm upgrade
   └─> Redirect to Stripe checkout
```

**Output Artefacts:**
- `frontend/src/pages/organizations/ConnectOrganization.tsx`
- `frontend/src/pages/organizations/OrganizationDashboard.tsx`
- `frontend/src/components/organizations/AccountTree.tsx`
- `frontend/src/components/organizations/OrgCoverageGauge.tsx`
- Updated sidebar navigation

**Dependencies:** Phase 5 (coverage API exists)

---

## Integration Checkpoints

### Checkpoint 1: Billing → Data Model
- [ ] `billing_config.py` tier limits enforced by `require_org_features` dependency
- [ ] Subscription model `org_features_enabled` flag used in API guards
- [ ] Account creation blocked when `max_accounts` exceeded

### Checkpoint 2: Data Model → Discovery Services
- [ ] `CloudOrganization` model correctly stores AWS/GCP org metadata
- [ ] `CloudOrganizationMember` tracks all discovered accounts
- [ ] Discovery services create proper model instances

### Checkpoint 3: Discovery → Scanners
- [ ] Org-level scanners use correct credentials (management/delegated admin)
- [ ] Detections created with `detection_scope='organization'`
- [ ] `applies_to_account_ids` correctly populated

### Checkpoint 4: Scanners → Coverage
- [ ] Coverage calculator includes org detections in account coverage
- [ ] No double-counting of shared detections
- [ ] `CoverageSnapshot` tracks org contribution

### Checkpoint 5: Coverage → Frontend
- [ ] API responses include org coverage breakdown
- [ ] Dashboard correctly displays aggregate metrics
- [ ] Hierarchy tree matches backend data

---

## Agent Invocation Order

For the Cloud Organisation & Billing feature, invoke agents in this order:

```
1. DATA-MODEL-AGENT (billing)     → AccountTier enum, billing_config
   ↓
2. DATA-MODEL-AGENT (org)         → CloudOrganization, CloudOrganizationMember
   ↓
3. API-DESIGN-AGENT               → /cloud-organizations endpoints
   ↓
4. PARSER-AGENT (AWS)             → AWS org discovery & scanners
   ↓  (parallel)
5. PARSER-AGENT (GCP)             → GCP org discovery & scanners
   ↓
6. ANALYSIS-AGENT                 → Coverage calculation updates
   ↓
7. UI-DESIGN-AGENT                → Organisation UX
   ↓
8. TESTING-AGENT                  → Integration & E2E tests
```

**Parallel Work Opportunities:**
- Phases 3 & 4 (AWS & GCP org integration) can run in parallel
- Frontend skeleton can start after Phase 2 with mocked data
- Testing can begin per-phase, not just at end

---

## Decision Log

### D1: Billing Tier Enforcement
- **Date:** 2024-12-20
- **Decision:** Backend-enforced via `require_org_features` FastAPI dependency
- **Rationale:** UI-only gates can be bypassed; database constraints plus API guards provide defence in depth
- **Alternatives Considered:** Frontend-only (insecure), database triggers (complex)

### D2: Org Member Lifecycle
- **Date:** 2024-12-20
- **Decision:** Separate `CloudOrganizationMember` table for discovered-but-not-connected accounts
- **Rationale:** Allows tracking discovery state, selective connection, and re-discovery without losing linked `CloudAccount` relationships
- **Alternatives Considered:** Merge into `CloudAccount` (conflates concerns)

### D3: Hierarchy Storage
- **Date:** 2024-12-20
- **Decision:** Materialised path (`Root/Production/WebServices`) stored in `hierarchy_path`
- **Rationale:** Human-readable, efficient for queries, works identically for AWS OUs and GCP Folders
- **Alternatives Considered:** Adjacency list (requires recursive queries), nested sets (complex updates)

### D4: Org Detection Inheritance
- **Date:** 2024-12-20
- **Decision:** Per-detection configuration: `applies_to_all_accounts` or `applies_to_account_ids` JSONB array
- **Rationale:** Flexible; org CloudTrail applies to all, but Config Aggregator may cover subset of regions
- **Alternatives Considered:** Always all (too rigid), hierarchy-based (complex to implement)

### D5: Coverage Aggregation
- **Date:** 2024-12-20
- **Decision:** Show both "minimum coverage" (all accounts covered) and "union coverage" (any account covered)
- **Rationale:** Different perspectives useful: executives want union, security teams want minimum
- **Alternatives Considered:** Single view (loses information)

---

## Open Questions

### OQ1: Cross-Account Role Deployment
**Question:** How do we help users deploy the cross-account role for member account scanning?

**Options:**
1. Provide CloudFormation StackSet template (user deploys manually)
2. Provide Terraform module
3. Auto-deploy via AWS CloudFormation StackSet API (requires additional permissions)

**Recommendation:** Option 1 (CFN template) with Option 2 (Terraform) for IaC users. Avoid Option 3 due to permission complexity.

**Status:** Pending user feedback

### OQ2: Delegated Admin Selection
**Question:** If an organisation has multiple delegated admins (e.g., one for GuardDuty, another for Security Hub), how do we handle scanning?

**Options:**
1. Require credentials for each delegated admin (complex)
2. Scan from management account only (may miss member-specific findings)
3. Auto-discover and prompt user for each delegated admin credential

**Recommendation:** Option 3 - discover delegated admins during org discovery, prompt user to provide credentials for desired services.

**Status:** Pending implementation review

### OQ3: Large Organisation Performance
**Question:** How do we handle orgs with 500+ accounts efficiently?

**Mitigation Strategies:**
- Batch discovery (50 accounts per API call where supported)
- Parallel account scanning (rate limit aware)
- Incremental scanning (only changed accounts)
- Progress indicators in UI

**Status:** To be addressed in Phase 3/4 implementation

---

## Success Criteria

### Technical
- [ ] AWS and GCP orgs can be connected with appropriate credentials
- [ ] All member accounts discovered and displayed in hierarchy
- [ ] Org-level detections correctly attributed and scoped
- [ ] Coverage calculation includes org detection inheritance
- [ ] Pro tier gate correctly blocks org features for lower tiers

### Practical
- [ ] Connection flow completable in < 5 minutes for typical org
- [ ] Org dashboard loads in < 3 seconds
- [ ] Scan performance: 1000 accounts in < 30 minutes (parallel)
- [ ] Clear error messages for permission issues

### Business
- [ ] Upgrade path from Individual to Pro is clear and compelling
- [ ] Org features provide clear value over individual account scanning
- [ ] Enterprise tier value prop established (SSO, SLAs, custom)

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| AWS rate limiting on large orgs | Medium | High | Exponential backoff, parallel per-service |
| GCP permission complexity | Medium | Medium | Clear permission documentation, validation script |
| Stripe price migration breaks existing customers | Low | High | Create new products, grandfather existing |
| Org hierarchy too deep to display | Low | Low | Collapse by default, lazy load |
| Users expect auto-remediation | Low | Medium | Clear messaging: analysis tool, not auto-fix |

---

## Next Steps

1. **Review this plan** with stakeholders
2. **Resolve open questions** (OQ1, OQ2, OQ3)
3. **Begin Phase 1** - Billing model update (least dependencies)
4. **Parallel frontend skeleton** - Start UI wireframes
5. **Set up staging environment** - Needed for integration testing

---

**Document Version:** 1.0
**Created:** 2024-12-20
**Author:** Master Orchestrator Agent
