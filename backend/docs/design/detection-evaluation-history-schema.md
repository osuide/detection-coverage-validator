# Detection Evaluation History Schema Design

## Overview

This document describes the database schema for tracking historical changes to detection evaluation/compliance status over time. This enables compliance trends, drift detection, and alerting.

## Entity Landscape Analysis

### Core Entity: Detection Evaluation History

**Purpose:** Store point-in-time snapshots of detection evaluation states

**Relationships:**
- M:1 with Detection (many history records per detection)
- M:1 with CloudAccount (inherited via detection, but denormalised for query performance)
- M:1 with Scan (optional - tracks which scan triggered the evaluation)

**Mutability:** Records are immutable once created (append-only time-series)

**Volume Estimates:**
- 1000 accounts x 100 detections/account = 100,000 detections
- Daily evaluations = 100,000 records/day
- 90-day retention = 9 million records
- With hourly evaluations for critical = up to 72 million records

**Access Patterns:**
1. "Show compliance trend for detection X over last 30 days" (by detection_id, time range)
2. "Show all non-compliant detections for account Y today" (by account, state, date)
3. "When did detection X first become non-compliant?" (by detection_id, state change)
4. "Calculate compliance percentage for account Y on date Z" (aggregation)
5. "List detections that changed state in last 24 hours" (state drift)

## Database Technology Choice

**Recommendation: PostgreSQL with BRIN indexing**

**Rationale:**
- Already using PostgreSQL for the application
- BRIN indexes are ideal for time-series append-only data (very compact)
- Built-in partitioning for table management and retention
- JSONB for flexible evaluation data storage
- Strong consistency for compliance reporting

**Considered Alternatives:**
- TimescaleDB: Overkill for this use case, adds operational complexity
- DynamoDB: Would require separate infrastructure
- ClickHouse: Better for analytics, but this is operational data

## Schema Design

### 1. Main History Table

```sql
-- Stores individual evaluation snapshots
CREATE TABLE detection_evaluation_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Detection reference
    detection_id UUID NOT NULL REFERENCES detections(id) ON DELETE CASCADE,

    -- Denormalised for query performance (avoid joins)
    cloud_account_id UUID NOT NULL,
    detection_type VARCHAR(64) NOT NULL,

    -- Evaluation state
    evaluation_type VARCHAR(32) NOT NULL,  -- 'config_compliance', 'alarm_state', 'eventbridge_state'

    -- Previous and current state for change tracking
    previous_state VARCHAR(32),  -- NULL for first record
    current_state VARCHAR(32) NOT NULL,  -- 'COMPLIANT', 'NON_COMPLIANT', 'OK', 'ALARM', 'ENABLED', etc.

    -- State changed flag (for filtering drift)
    state_changed BOOLEAN NOT NULL DEFAULT FALSE,

    -- Full evaluation summary snapshot
    evaluation_summary JSONB NOT NULL,

    -- Scan that triggered this evaluation (optional)
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,

    -- Timestamp (partition key for BRIN index)
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Partition constraint
    CONSTRAINT pk_detection_evaluation_history PRIMARY KEY (id, recorded_at)
) PARTITION BY RANGE (recorded_at);
```

### 2. Partitioning Strategy

Monthly partitions for manageability:

```sql
-- Create partitions for current and next 3 months
CREATE TABLE detection_evaluation_history_2025_01
    PARTITION OF detection_evaluation_history
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE detection_evaluation_history_2025_02
    PARTITION OF detection_evaluation_history
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

-- ... etc
```

### 3. Indexing Strategy

```sql
-- BRIN index on timestamp (very efficient for time-series)
CREATE INDEX idx_eval_history_recorded_at_brin
    ON detection_evaluation_history USING BRIN (recorded_at);

-- B-tree indexes for common query patterns
CREATE INDEX idx_eval_history_detection_time
    ON detection_evaluation_history (detection_id, recorded_at DESC);

CREATE INDEX idx_eval_history_account_time
    ON detection_evaluation_history (cloud_account_id, recorded_at DESC);

-- Partial index for state changes only (drift detection)
CREATE INDEX idx_eval_history_state_changes
    ON detection_evaluation_history (detection_id, recorded_at DESC)
    WHERE state_changed = TRUE;

-- Partial index for non-compliant states (compliance reporting)
CREATE INDEX idx_eval_history_non_compliant
    ON detection_evaluation_history (cloud_account_id, recorded_at DESC)
    WHERE current_state IN ('NON_COMPLIANT', 'ALARM', 'DISABLED');
```

### 4. Daily Aggregation Table

Pre-computed daily summaries for dashboard performance:

```sql
CREATE TABLE detection_evaluation_daily_summary (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Keys
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    summary_date DATE NOT NULL,

    -- Detection type breakdown
    detection_type VARCHAR(64) NOT NULL,

    -- Aggregate counts
    total_detections INTEGER NOT NULL DEFAULT 0,
    compliant_count INTEGER NOT NULL DEFAULT 0,
    non_compliant_count INTEGER NOT NULL DEFAULT 0,
    alarm_count INTEGER NOT NULL DEFAULT 0,
    ok_count INTEGER NOT NULL DEFAULT 0,
    enabled_count INTEGER NOT NULL DEFAULT 0,
    disabled_count INTEGER NOT NULL DEFAULT 0,
    unknown_count INTEGER NOT NULL DEFAULT 0,

    -- State changes that day
    state_changes_count INTEGER NOT NULL DEFAULT 0,

    -- Derived metrics
    compliance_rate DECIMAL(5,2),  -- 0.00 to 100.00

    -- Metadata
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(cloud_account_id, summary_date, detection_type)
);

CREATE INDEX idx_eval_daily_account_date
    ON detection_evaluation_daily_summary (cloud_account_id, summary_date DESC);
```

### 5. Evaluation Alerts Table

For tracking significant state changes:

```sql
CREATE TABLE detection_evaluation_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- References
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    detection_id UUID REFERENCES detections(id) ON DELETE CASCADE,
    evaluation_history_id UUID,  -- No FK to partitioned table

    -- Alert details
    alert_type VARCHAR(64) NOT NULL,  -- 'state_change', 'compliance_drop', 'alarm_triggered'
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),

    -- State change details
    previous_state VARCHAR(32),
    current_state VARCHAR(32) NOT NULL,

    -- Human-readable message
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,

    -- Additional context
    details JSONB NOT NULL DEFAULT '{}',

    -- Acknowledgement workflow
    is_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID REFERENCES users(id),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Indexes
    INDEX idx_eval_alerts_org (organization_id, created_at DESC),
    INDEX idx_eval_alerts_account (cloud_account_id, created_at DESC),
    INDEX idx_eval_alerts_unacked (organization_id, is_acknowledged) WHERE is_acknowledged = FALSE
);
```

## Views

### 1. Current Evaluation State View

```sql
CREATE VIEW v_detection_current_evaluation AS
SELECT DISTINCT ON (detection_id)
    detection_id,
    cloud_account_id,
    detection_type,
    evaluation_type,
    current_state,
    evaluation_summary,
    recorded_at
FROM detection_evaluation_history
ORDER BY detection_id, recorded_at DESC;
```

### 2. Daily Compliance Trend View

```sql
CREATE VIEW v_daily_compliance_trend AS
SELECT
    cloud_account_id,
    summary_date,
    SUM(total_detections) as total_detections,
    SUM(compliant_count) + SUM(ok_count) + SUM(enabled_count) as healthy_count,
    SUM(non_compliant_count) + SUM(alarm_count) + SUM(disabled_count) as unhealthy_count,
    ROUND(
        (SUM(compliant_count) + SUM(ok_count) + SUM(enabled_count))::DECIMAL /
        NULLIF(SUM(total_detections), 0) * 100,
        2
    ) as health_percentage
FROM detection_evaluation_daily_summary
GROUP BY cloud_account_id, summary_date
ORDER BY cloud_account_id, summary_date DESC;
```

### 3. State Change Summary View

```sql
CREATE VIEW v_recent_state_changes AS
SELECT
    h.detection_id,
    d.name as detection_name,
    h.cloud_account_id,
    h.detection_type,
    h.previous_state,
    h.current_state,
    h.recorded_at,
    h.evaluation_summary
FROM detection_evaluation_history h
JOIN detections d ON h.detection_id = d.id
WHERE h.state_changed = TRUE
  AND h.recorded_at > NOW() - INTERVAL '7 days'
ORDER BY h.recorded_at DESC;
```

## Query Patterns

### 1. Compliance Trend for Detection (Last 30 Days)

```sql
-- Expected: < 50ms with index
SELECT
    DATE_TRUNC('day', recorded_at) as day,
    current_state,
    COUNT(*) as sample_count
FROM detection_evaluation_history
WHERE detection_id = $1
  AND recorded_at > NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', recorded_at), current_state
ORDER BY day;
```

### 2. All Non-Compliant Detections for Account

```sql
-- Expected: < 100ms with partial index
SELECT DISTINCT ON (detection_id)
    detection_id,
    current_state,
    evaluation_summary,
    recorded_at
FROM detection_evaluation_history
WHERE cloud_account_id = $1
  AND current_state IN ('NON_COMPLIANT', 'ALARM', 'DISABLED')
  AND recorded_at > NOW() - INTERVAL '24 hours'
ORDER BY detection_id, recorded_at DESC;
```

### 3. State Changes in Last 24 Hours

```sql
-- Expected: < 50ms with partial index
SELECT
    detection_id,
    previous_state,
    current_state,
    evaluation_summary,
    recorded_at
FROM detection_evaluation_history
WHERE cloud_account_id = $1
  AND state_changed = TRUE
  AND recorded_at > NOW() - INTERVAL '24 hours'
ORDER BY recorded_at DESC;
```

### 4. Daily Compliance Percentage Trend

```sql
-- Expected: < 20ms using aggregation table
SELECT
    summary_date,
    SUM(total_detections) as total,
    SUM(compliant_count + ok_count + enabled_count) as healthy,
    ROUND(
        SUM(compliant_count + ok_count + enabled_count)::DECIMAL /
        NULLIF(SUM(total_detections), 0) * 100,
        2
    ) as health_pct
FROM detection_evaluation_daily_summary
WHERE cloud_account_id = $1
  AND summary_date > CURRENT_DATE - INTERVAL '90 days'
GROUP BY summary_date
ORDER BY summary_date;
```

## Retention Strategy

### Tiered Retention Policy

| Data Type | Retention | Rationale |
|-----------|-----------|-----------|
| Raw evaluation history | 90 days | Detailed debugging, audit |
| Daily summaries | 2 years | Trend analysis, compliance reporting |
| Alerts | 1 year | Incident history |

### Partition Management

```sql
-- Run monthly via pg_cron or application scheduler

-- Drop old raw history partitions (> 90 days)
DROP TABLE IF EXISTS detection_evaluation_history_2024_10;

-- Create future partitions (3 months ahead)
CREATE TABLE IF NOT EXISTS detection_evaluation_history_2025_04
    PARTITION OF detection_evaluation_history
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
```

### Cleanup Function

```sql
CREATE OR REPLACE FUNCTION cleanup_evaluation_history() RETURNS void AS $$
DECLARE
    partition_name TEXT;
    cutoff_date DATE := CURRENT_DATE - INTERVAL '90 days';
BEGIN
    -- Find and drop partitions older than 90 days
    FOR partition_name IN
        SELECT inhrelid::regclass::text
        FROM pg_inherits
        WHERE inhparent = 'detection_evaluation_history'::regclass
        AND inhrelid::regclass::text ~ '_\d{4}_\d{2}$'
    LOOP
        -- Extract date from partition name and check if too old
        -- Implementation depends on naming convention
        EXECUTE format('DROP TABLE IF EXISTS %I', partition_name);
        RAISE NOTICE 'Dropped partition: %', partition_name;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
```

## Storage Estimates

### Per-Record Size

| Field | Size (bytes) |
|-------|--------------|
| id (UUID) | 16 |
| detection_id (UUID) | 16 |
| cloud_account_id (UUID) | 16 |
| detection_type (VARCHAR 64) | ~32 |
| evaluation_type (VARCHAR 32) | ~16 |
| previous_state (VARCHAR 32) | ~16 |
| current_state (VARCHAR 32) | ~16 |
| state_changed (BOOLEAN) | 1 |
| evaluation_summary (JSONB) | ~200 |
| scan_id (UUID) | 16 |
| recorded_at (TIMESTAMPTZ) | 8 |
| **Total** | **~350 bytes** |

### Volume Projections

| Scenario | Daily Records | Monthly Storage | Yearly Storage |
|----------|---------------|-----------------|----------------|
| Small (10 accounts, 50 detections/account, daily) | 500 | 5 MB | 60 MB |
| Medium (100 accounts, 100 detections/account, daily) | 10,000 | 105 MB | 1.2 GB |
| Large (1000 accounts, 100 detections/account, daily) | 100,000 | 1 GB | 12 GB |
| Enterprise (1000 accounts, 200 detections/account, hourly) | 4.8M | 50 GB | 600 GB |

### Index Overhead

Expect ~40% additional storage for indexes, bringing enterprise yearly to ~840 GB.

## Migration Strategy

### Phase 1: Create Tables (Non-blocking)

1. Create partitioned table with initial partitions
2. Create aggregation table
3. Create alerts table
4. Create indexes

### Phase 2: Backfill (Optional)

If needed, backfill from current `evaluation_summary` field:

```sql
INSERT INTO detection_evaluation_history (
    detection_id,
    cloud_account_id,
    detection_type,
    evaluation_type,
    current_state,
    evaluation_summary,
    recorded_at
)
SELECT
    d.id,
    d.cloud_account_id,
    d.detection_type::text,
    d.evaluation_summary->>'type',
    COALESCE(
        d.evaluation_summary->>'compliance_type',
        d.evaluation_summary->>'state',
        'UNKNOWN'
    ),
    d.evaluation_summary,
    COALESCE(d.evaluation_updated_at, d.updated_at)
FROM detections d
WHERE d.evaluation_summary IS NOT NULL;
```

### Phase 3: Application Integration

1. Modify scan service to write to history table
2. Add background job for daily summary calculation
3. Add alert generation logic

## Rollback Plan

```sql
-- Safe rollback - tables are independent
DROP TABLE IF EXISTS detection_evaluation_alerts CASCADE;
DROP TABLE IF EXISTS detection_evaluation_daily_summary CASCADE;
DROP TABLE IF EXISTS detection_evaluation_history CASCADE;

-- Views are automatically dropped with tables
```

## Performance Considerations

### Query Optimisation

1. **Use partition pruning**: Always include `recorded_at` in WHERE clause
2. **Avoid SELECT ***: Only fetch needed columns
3. **Use aggregation table**: For dashboard queries, use pre-computed summaries
4. **Limit result sets**: Use LIMIT for UI queries

### Write Optimisation

1. **Batch inserts**: Insert multiple records per transaction
2. **Skip unchanged states**: Only write when state actually changes (configurable)
3. **Async writes**: Use background job for non-critical history

### Monitoring

```sql
-- Monitor partition sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) as size
FROM pg_tables
WHERE tablename LIKE 'detection_evaluation_history%'
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC;

-- Monitor query performance
SELECT * FROM pg_stat_user_tables
WHERE relname LIKE 'detection_evaluation%';
```

## Open Questions

1. **Sampling frequency**: Should we record every evaluation or only on state change?
   - Recommendation: Record on state change + daily snapshot for trend continuity

2. **Compression**: Should we enable TOAST compression for JSONB?
   - Recommendation: PostgreSQL auto-compresses JSONB > 2KB

3. **Read replicas**: Should history queries go to a read replica?
   - Recommendation: Yes, if query volume is high

4. **Real-time alerts**: Should alerts be generated synchronously or via background job?
   - Recommendation: Background job to avoid scan latency impact
