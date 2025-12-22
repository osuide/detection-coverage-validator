# Clickable Coverage Cards Implementation Plan

## Objective
Make the compliance coverage stat cards (Covered, Partial, Uncovered, Total) and Cloud Detection Analytics cards clickable to show detailed control-level information.

## Available Data (Verified from Codebase)

### Control-Level Fields
- `control_id`, `name`, `control_family`, `description`
- `priority` (P1/P2/P3)
- `cloud_applicability` (highly_relevant, moderately_relevant, informational, provider_responsibility)
- `coverage_percent`, `mapped_technique_count`, `covered_technique_count`
- `missing_techniques` (list of technique IDs)
- `cloud_context.aws_services`, `cloud_context.gcp_services`
- `cloud_context.shared_responsibility` (customer/shared/provider)

### Cloud Metrics
- `cloud_detectable_total`, `cloud_detectable_covered`, `cloud_coverage_percent`
- `customer_responsibility_total`, `customer_responsibility_covered`
- `provider_managed_total`, `not_assessable_total`

## Implementation Plan

### Phase 1: Backend - Add Controls by Status to API Response
**File:** `backend/app/schemas/compliance.py`
**File:** `backend/app/api/routes/compliance.py`

Add new field to `ComplianceCoverageResponse`:
```python
controls_by_status: dict[str, list[ControlSummaryItem]]
```

Where `ControlSummaryItem` contains:
- control_id, name, control_family
- priority, coverage_percent
- cloud_applicability, shared_responsibility
- technique_coverage: "X/Y techniques covered"

### Phase 2: Frontend - Create CoverageDetailModal
**File:** `frontend/src/components/compliance/CoverageDetailModal.tsx`

Modal that displays:
- Title: "Covered Controls" / "Partial Controls" / etc.
- Count summary
- Scrollable list of controls with:
  - Control ID and name
  - Priority badge
  - Coverage percentage bar
  - Cloud applicability indicator
  - "X/Y techniques" coverage

### Phase 3: Make Stat Cards Clickable
**File:** `frontend/src/components/compliance/ComplianceCoverageContent.tsx`

Update the Covered/Partial/Uncovered/Total cards:
- Add onClick handler
- Add hover cursor and visual feedback
- Open modal with filtered controls

### Phase 4: Cloud Metrics Cards
Same pattern for:
- Cloud-Detectable → Show controls that can be detected via cloud scanning
- Customer Responsibility → Show controls customer must cover
- Provider Managed → Show controls managed by AWS/GCP
- Not Assessable → Show controls outside cloud scanning scope

## Information to Display (Validated, No Made-Up Data)

### Covered Controls Modal
- List of controls with 80%+ technique coverage
- Show: ID, Name, Family, Priority, "X/Y techniques covered"
- Green visual indicator

### Partial Controls Modal
- List of controls with 40-79% technique coverage
- Show: ID, Name, Family, Priority, "X/Y techniques covered"
- Show missing techniques count
- Yellow visual indicator

### Uncovered Controls Modal
- List of controls with <40% technique coverage
- Show: ID, Name, Family, Priority, "X/Y techniques covered"
- Link to View Template for missing techniques
- Red visual indicator

### Cloud-Detectable Modal
- Controls that can be assessed via cloud log scanning
- Shows cloud_applicability = highly_relevant or moderately_relevant

### Customer Responsibility Modal
- Controls where shared_responsibility = "customer"
- These are the user's responsibility to cover

### Provider Managed Modal
- Controls where shared_responsibility = "provider"
- Managed by AWS/GCP (e.g., physical security, hardware)

### Not Assessable Modal
- Controls with cloud_applicability = "informational" or "provider_responsibility"
- Explains why: training, physical security, governance, etc.

## Progress Tracking
- [x] Phase 1: Backend API changes
- [x] Phase 2: CoverageDetailModal component
- [x] Phase 3: Clickable stat cards
- [x] Phase 4: Clickable cloud metrics cards
- [ ] Testing on staging
