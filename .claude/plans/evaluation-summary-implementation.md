# Detection Evaluation Summary Implementation Plan

## Problem Statement

Config rules like `s3-bucket-versioning-enabled` are shown as "Active" detections even when resources are non-compliant. This creates a false sense of security - users see "Active Detection" and think they're covered, when their buckets actually lack versioning.

## Solution Overview

Add an `evaluation_summary` JSONB field to the Detection model to store type-specific evaluation/compliance data. This provides the flexibility to store different data for different detection types while maintaining a clean schema.

---

## Phase 1: Config Rule Compliance (MVP)

### 1.1 Database Migration

**File:** `backend/alembic/versions/037_add_evaluation_summary.py`

```python
"""Add evaluation_summary field to detections.

Revision ID: 037_add_evaluation_summary
Revises: 036_add_cloud_relevant_flag
Create Date: 2025-12-27
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "037_add_evaluation_summary"
down_revision = "036_add_cloud_relevant_flag"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add evaluation_summary JSONB field
    op.add_column(
        "detections",
        sa.Column("evaluation_summary", JSONB, nullable=True, default=dict),
    )

    # Add evaluation_updated_at timestamp
    op.add_column(
        "detections",
        sa.Column(
            "evaluation_updated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Create GIN index for JSONB queries
    op.create_index(
        "ix_detections_evaluation_summary",
        "detections",
        ["evaluation_summary"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_detections_evaluation_summary")
    op.drop_column("detections", "evaluation_updated_at")
    op.drop_column("detections", "evaluation_summary")
```

### 1.2 Update Detection Model

**File:** `backend/app/models/detection.py`

Add fields after `target_services`:

```python
# Evaluation/compliance summary (type-specific)
# For Config Rules: {"type": "config_compliance", "compliance_type": "NON_COMPLIANT", ...}
# For CloudWatch Alarms: {"type": "alarm_state", "state": "ALARM", ...}
evaluation_summary: Mapped[Optional[dict]] = mapped_column(
    JSONB, nullable=True, default=dict
)
evaluation_updated_at: Mapped[Optional[datetime]] = mapped_column(
    DateTime(timezone=True), nullable=True
)
```

### 1.3 Update RawDetection Dataclass

**File:** `backend/app/scanners/base.py`

Add field to RawDetection:

```python
# Evaluation/compliance data (type-specific)
evaluation_summary: Optional[dict[str, Any]] = None
```

### 1.4 Update Config Scanner

**File:** `backend/app/scanners/aws/config_scanner.py`

Add compliance fetching after rule discovery:

```python
async def scan_region(self, region: str, options: Optional[dict[str, Any]] = None) -> list[RawDetection]:
    """Scan a single region for Config Rules."""
    detections = []
    client = self.session.client("config", region_name=region)

    try:
        # List all Config Rules
        paginator = client.get_paginator("describe_config_rules")
        rules = []

        for page in paginator.paginate():
            for rule in page.get("ConfigRules", []):
                rules.append(rule)

        # Fetch compliance for all rules (batch of 25)
        compliance_map = await self._fetch_compliance_summary(client, rules)

        # Create detections with compliance data
        for rule in rules:
            detection = self._parse_config_rule(rule, region, compliance_map)
            if detection:
                detections.append(detection)

    except ClientError as e:
        # ... existing error handling ...

    return detections


async def _fetch_compliance_summary(
    self,
    client,
    rules: list[dict]
) -> dict[str, dict]:
    """Fetch compliance summary for config rules.

    Returns dict mapping rule_name -> compliance_data
    """
    compliance_map = {}
    rule_names = [r.get("ConfigRuleName") for r in rules if r.get("ConfigRuleName")]

    # Batch in groups of 25 (API limit)
    for i in range(0, len(rule_names), 25):
        batch = rule_names[i:i + 25]
        try:
            response = client.describe_compliance_by_config_rule(
                ConfigRuleNames=batch
            )

            for item in response.get("ComplianceByConfigRules", []):
                rule_name = item.get("ConfigRuleName")
                compliance = item.get("Compliance", {})
                compliance_map[rule_name] = {
                    "type": "config_compliance",
                    "compliance_type": compliance.get("ComplianceType", "INSUFFICIENT_DATA"),
                    "non_compliant_count": compliance.get(
                        "ComplianceContributorCount", {}
                    ).get("CappedCount", 0),
                    "cap_exceeded": compliance.get(
                        "ComplianceContributorCount", {}
                    ).get("CapExceeded", False),
                }

        except ClientError as e:
            self.logger.warning(
                "compliance_fetch_error",
                batch_size=len(batch),
                error=str(e)
            )

    return compliance_map


def _parse_config_rule(
    self,
    rule: dict,
    region: str,
    compliance_map: dict[str, dict],
) -> Optional[RawDetection]:
    """Parse a Config Rule into a RawDetection."""
    rule_name = rule.get("ConfigRuleName", "")
    # ... existing parsing logic ...

    # Get compliance data
    evaluation_summary = compliance_map.get(rule_name)

    return RawDetection(
        name=rule_name,
        # ... existing fields ...
        evaluation_summary=evaluation_summary,
    )
```

### 1.5 Update Scan Service

**File:** `backend/app/services/scan_service.py`

Update detection persistence to include evaluation_summary:

```python
# In _save_raw_detections method:

if detection:
    # Update existing
    detection.name = raw.name
    detection.raw_config = _serialize_for_jsonb(raw.raw_config)
    # ... existing fields ...
    detection.evaluation_summary = raw.evaluation_summary
    detection.evaluation_updated_at = datetime.now(timezone.utc) if raw.evaluation_summary else None
    detection.status = self._determine_status(raw)  # NEW: Determine status from evaluation
else:
    # Create new
    detection = Detection(
        # ... existing fields ...
        evaluation_summary=raw.evaluation_summary,
        evaluation_updated_at=datetime.now(timezone.utc) if raw.evaluation_summary else None,
    )


def _determine_status(self, raw: RawDetection) -> DetectionStatus:
    """Determine detection status based on evaluation data."""
    # Check rule state in raw_config
    rule_state = raw.raw_config.get("rule_state", "ACTIVE")

    if rule_state not in ("ACTIVE", "EVALUATING"):
        return DetectionStatus.DISABLED

    return DetectionStatus.ACTIVE
```

### 1.6 Update API Schemas

**File:** `backend/app/schemas/detection.py`

Add evaluation fields:

```python
from typing import Literal

class EvaluationSummaryBase(BaseModel):
    """Base evaluation summary."""
    type: str


class ConfigComplianceEvaluation(EvaluationSummaryBase):
    """Config rule compliance evaluation."""
    type: Literal["config_compliance"] = "config_compliance"
    compliance_type: str  # COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE, INSUFFICIENT_DATA
    non_compliant_count: int = 0
    cap_exceeded: bool = False


class AlarmStateEvaluation(EvaluationSummaryBase):
    """CloudWatch alarm state evaluation."""
    type: Literal["alarm_state"] = "alarm_state"
    state: str  # OK, ALARM, INSUFFICIENT_DATA
    state_reason: Optional[str] = None


class DetectionResponse(BaseModel):
    """Schema for detection response."""
    # ... existing fields ...

    # New evaluation fields
    evaluation_summary: Optional[dict[str, Any]] = None
    evaluation_updated_at: Optional[datetime] = None

    # Computed helper properties
    @property
    def is_compliant(self) -> Optional[bool]:
        """Check if detection is compliant (for Config rules)."""
        if not self.evaluation_summary:
            return None
        if self.evaluation_summary.get("type") != "config_compliance":
            return None
        return self.evaluation_summary.get("compliance_type") == "COMPLIANT"
```

### 1.7 Update Frontend Types

**File:** `frontend/src/services/api.ts`

```typescript
export interface EvaluationSummary {
  type: 'config_compliance' | 'alarm_state' | 'security_hub_status'
  // Config compliance fields
  compliance_type?: 'COMPLIANT' | 'NON_COMPLIANT' | 'NOT_APPLICABLE' | 'INSUFFICIENT_DATA'
  non_compliant_count?: number
  cap_exceeded?: boolean
  // Alarm state fields
  state?: 'OK' | 'ALARM' | 'INSUFFICIENT_DATA'
  state_reason?: string
}

export interface Detection {
  id: string
  cloud_account_id: string
  name: string
  detection_type: string
  status: string
  region: string
  mapping_count: number
  discovered_at: string
  // New fields
  evaluation_summary?: EvaluationSummary
  evaluation_updated_at?: string
}

export interface DetectionDetail extends Detection {
  source_arn: string
  query_pattern: string | null
  event_pattern: object | null
  log_groups: string[] | null
  description: string | null
  health_score: number | null
  is_managed: boolean
  // Inherited evaluation fields from Detection
}
```

### 1.8 Update Frontend Components

**File:** `frontend/src/pages/Detections.tsx`

Add compliance indicator to table:

```tsx
function ComplianceIndicator({ evaluation }: { evaluation?: EvaluationSummary }) {
  if (!evaluation) return null

  if (evaluation.type === 'config_compliance') {
    const { compliance_type, non_compliant_count } = evaluation

    if (compliance_type === 'COMPLIANT') {
      return (
        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-green-900/30 text-green-400">
          <CheckCircle className="h-3 w-3 mr-1" />
          Compliant
        </span>
      )
    }

    if (compliance_type === 'NON_COMPLIANT') {
      return (
        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-red-900/30 text-red-400">
          <AlertTriangle className="h-3 w-3 mr-1" />
          {non_compliant_count} non-compliant
        </span>
      )
    }

    return (
      <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-gray-700/30 text-gray-400">
        {compliance_type}
      </span>
    )
  }

  return null
}
```

Add column to table:

```tsx
<SortHeader field="status">Status</SortHeader>
<th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
  Compliance
</th>

// In row:
<td className="px-6 py-4">
  <ComplianceIndicator evaluation={detection.evaluation_summary} />
</td>
```

**File:** `frontend/src/components/DetectionDetailModal.tsx`

Add compliance card:

```tsx
{/* Compliance Status (for Config rules) */}
{detectionDetail?.evaluation_summary?.type === 'config_compliance' && (
  <div className="mb-6">
    <h3 className="text-sm font-semibold text-gray-700 mb-2">Compliance Status</h3>
    <div className={`p-4 rounded-lg ${
      detectionDetail.evaluation_summary.compliance_type === 'COMPLIANT'
        ? 'bg-green-50 border border-green-200'
        : detectionDetail.evaluation_summary.compliance_type === 'NON_COMPLIANT'
        ? 'bg-red-50 border border-red-200'
        : 'bg-gray-50 border border-gray-200'
    }`}>
      <div className="flex items-center justify-between">
        <span className={`font-medium ${
          detectionDetail.evaluation_summary.compliance_type === 'COMPLIANT'
            ? 'text-green-800'
            : detectionDetail.evaluation_summary.compliance_type === 'NON_COMPLIANT'
            ? 'text-red-800'
            : 'text-gray-800'
        }`}>
          {detectionDetail.evaluation_summary.compliance_type}
        </span>
        {detectionDetail.evaluation_summary.non_compliant_count > 0 && (
          <span className="text-red-600 text-sm">
            {detectionDetail.evaluation_summary.non_compliant_count} resources non-compliant
          </span>
        )}
      </div>
    </div>
  </div>
)}
```

---

## Phase 2: CloudWatch Alarm & EventBridge State

### 2.1 Update CloudWatch Scanner

**File:** `backend/app/scanners/aws/cloudwatch_scanner.py`

Extract alarm state from existing data:

```python
def _parse_alarm(self, alarm: dict, region: str) -> Optional[RawDetection]:
    """Parse a CloudWatch alarm."""

    # Extract evaluation summary from alarm state
    evaluation_summary = {
        "type": "alarm_state",
        "state": alarm.get("StateValue", "INSUFFICIENT_DATA"),
        "state_reason": alarm.get("StateReason"),
        "state_updated_at": alarm.get("StateUpdatedTimestamp"),
    }

    serialized_alarm = _serialize_for_json(alarm)
    return RawDetection(
        name=alarm.get("AlarmName", ""),
        detection_type=DetectionType.CLOUDWATCH_ALARM,
        source_arn=alarm.get("AlarmArn", ""),
        region=region,
        raw_config=serialized_alarm,
        description=alarm.get("AlarmDescription"),
        evaluation_summary=evaluation_summary,
    )
```

### 2.2 Update EventBridge Scanner

**File:** `backend/app/scanners/aws/eventbridge_scanner.py`

Extract rule state:

```python
def _parse_rule(self, rule: dict, region: str) -> Optional[RawDetection]:
    """Parse an EventBridge rule."""

    # Extract evaluation summary from rule state
    state = rule.get("State", "ENABLED")
    evaluation_summary = {
        "type": "eventbridge_state",
        "state": state,  # ENABLED or DISABLED
    }

    return RawDetection(
        # ... existing fields ...
        evaluation_summary=evaluation_summary,
    )
```

### 2.3 Update Frontend for Alarm States

Add alarm state indicator:

```tsx
function AlarmStateIndicator({ evaluation }: { evaluation?: EvaluationSummary }) {
  if (!evaluation || evaluation.type !== 'alarm_state') return null

  const { state } = evaluation

  if (state === 'OK') {
    return (
      <span className="inline-flex items-center px-2 py-1 text-xs rounded-full bg-green-900/30 text-green-400">
        OK
      </span>
    )
  }

  if (state === 'ALARM') {
    return (
      <span className="inline-flex items-center px-2 py-1 text-xs rounded-full bg-red-900/30 text-red-400">
        <Bell className="h-3 w-3 mr-1" />
        ALARM
      </span>
    )
  }

  return (
    <span className="inline-flex items-center px-2 py-1 text-xs rounded-full bg-gray-700/30 text-gray-400">
      {state}
    </span>
  )
}
```

---

## Phase 3: Historical Tracking & Trends

### 3.1 Create Evaluation History Table

**Migration:** `backend/alembic/versions/XXX_add_detection_evaluation_history.py`

```python
def upgrade() -> None:
    op.create_table(
        "detection_evaluation_history",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("detection_id", UUID(as_uuid=True), ForeignKey("detections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evaluation_summary", JSONB, nullable=False),
        sa.Column("evaluated_at", DateTime(timezone=True), nullable=False),
        sa.Column("created_at", DateTime(timezone=True), default=datetime.utcnow),
    )

    # Index for time-series queries
    op.create_index(
        "ix_detection_eval_history_detection_time",
        "detection_evaluation_history",
        ["detection_id", "evaluated_at"],
    )

    # Index for compliance type queries
    op.create_index(
        "ix_detection_eval_history_summary",
        "detection_evaluation_history",
        ["evaluation_summary"],
        postgresql_using="gin",
    )
```

### 3.2 Create History Model

```python
class DetectionEvaluationHistory(Base):
    """Historical record of detection evaluations."""

    __tablename__ = "detection_evaluation_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evaluation_summary: Mapped[dict] = mapped_column(JSONB, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    detection = relationship("Detection", back_populates="evaluation_history")
```

### 3.3 Track History on Scan

```python
async def _save_evaluation_history(
    self,
    detection: Detection,
    evaluation_summary: dict,
) -> None:
    """Save evaluation to history if changed."""
    # Check if evaluation changed
    if detection.evaluation_summary == evaluation_summary:
        return

    history = DetectionEvaluationHistory(
        detection_id=detection.id,
        evaluation_summary=evaluation_summary,
        evaluated_at=datetime.now(timezone.utc),
    )
    self.db.add(history)
```

### 3.4 Add Compliance Trends API

```python
@router.get("/detections/{detection_id}/compliance-history")
async def get_compliance_history(
    detection_id: UUID,
    days: int = 30,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
):
    """Get compliance history for a detection."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(DetectionEvaluationHistory)
        .where(DetectionEvaluationHistory.detection_id == detection_id)
        .where(DetectionEvaluationHistory.evaluated_at >= since)
        .order_by(DetectionEvaluationHistory.evaluated_at.asc())
    )

    history = result.scalars().all()

    return {
        "detection_id": detection_id,
        "history": [
            {
                "evaluated_at": h.evaluated_at.isoformat(),
                "evaluation_summary": h.evaluation_summary,
            }
            for h in history
        ]
    }
```

---

## Testing Plan

### Unit Tests

1. **Config Scanner Tests**
   - Test compliance fetching with mock responses
   - Test batch handling (>25 rules)
   - Test error handling when compliance API fails

2. **Scan Service Tests**
   - Test evaluation_summary persistence
   - Test status determination from rule state

3. **API Schema Tests**
   - Test serialisation of evaluation_summary
   - Test computed properties

### Integration Tests

1. **Full Scan Test**
   - Run scan against test account
   - Verify evaluation_summary populated
   - Verify frontend displays compliance

2. **Compliance Dashboard Test**
   - Verify Config rules show compliance status
   - Verify non-compliant count displayed

---

## Rollback Plan

If issues arise:

1. **Database**: Run `alembic downgrade -1` to remove new columns
2. **Code**: Revert changes to scanner and service
3. **Frontend**: Revert UI changes

The changes are backwards compatible - existing data won't be affected.

---

## Success Metrics

1. Config rules with non-compliant resources show "NON_COMPLIANT (X resources)"
2. Compliant rules show "COMPLIANT"
3. Users can distinguish between "detection exists" and "resources are compliant"
