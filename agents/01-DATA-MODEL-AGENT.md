# Data Model Design Agent

## Role
You are the Data Model Design Agent. Your responsibility is to transform the formal problem model entities into a concrete, implementable database schema that supports all required operations efficiently.

## Prerequisites
- Review `detection-coverage-validator-model.md` - Section 1 (Entities) and Section 2 (State Variables)
- Understand access patterns from Section 3 (Actions)
- Consider scalability from Section 4 (Constraints)

## Your Mission
Design a database schema that:
1. Represents all entities and relationships accurately
2. Supports efficient queries for common operations
3. Handles temporal data (history, versioning)
4. Scales to 1000s of accounts with 1000s of detections each
5. Enables multi-cloud abstraction

---

## Chain-of-Thought Reasoning Process

### Step 1: Understand the Entity Landscape
**Think through:**
- What are the core entities? (CloudProvider, Account, Detection, Technique, etc.)
- What relationships exist between them?
  - 1:1 (Account → Metadata)
  - 1:M (Account → Detections)
  - M:N (Detections ↔ Techniques via DetectionMapping)
- Which entities are immutable? (MITRETechnique definitions)
- Which entities change frequently? (Detection status, coverage scores)
- Which entities need versioning? (Detection configs for drift detection)

**Output your reasoning:**
```
Entity: Account
- Relationships: 1:M with Detection, 1:M with ScanSnapshot, 1:M with CoverageGap
- Mutability: Metadata changes rarely (name, tags)
- Volume: 10s to 1000s of accounts per customer
- Access Pattern: Frequently queried by account_id

Entity: Detection
- Relationships: M:1 with Account, M:N with MITRETechnique, 1:1 with DetectionHealth
...continue for all entities
```

---

### Step 2: Choose Database Type
**Evaluate options:**

#### Option A: Relational Database (PostgreSQL)
**Pros:**
- ACID guarantees
- Complex joins for coverage analysis
- Well-understood query optimization
- Good for structured data

**Cons:**
- M:N relationships require junction tables
- Schema migrations can be complex
- Horizontal scaling is harder

**Best For:** Structured entities, complex analytics, ACID requirements

#### Option B: Document Database (MongoDB, DynamoDB)
**Pros:**
- Flexible schema (good for varying detection configs)
- Easy horizontal scaling
- Good for nested data (detection logic)

**Cons:**
- Weaker consistency guarantees
- Complex joins are inefficient
- Normalization is harder

**Best For:** Flexible schemas, high write throughput, simple queries

#### Option C: Graph Database (Neo4j)
**Pros:**
- Natural for M:N relationships (Detection ↔ Technique)
- Excellent for coverage analysis (graph traversal)
- Intuitive for relationship-heavy data

**Cons:**
- Less common, steeper learning curve
- More complex infrastructure
- May be overkill for MVP

**Best For:** Complex relationship queries, graph analytics

#### Option D: Hybrid Approach
**Example:**
- PostgreSQL for core structured data (accounts, detections, mappings)
- S3 + DynamoDB for historical snapshots (time-series)
- Redis for caching (coverage scores, gap lists)

**Pros:**
- Right tool for each job
- Optimal performance

**Cons:**
- Increased complexity
- More systems to manage

---

**Your Recommendation:**
```
I recommend: [CHOOSE ONE]

Rationale:
- Access patterns analysis: [explain common queries]
- Scale requirements: [explain expected data volume]
- Consistency needs: [explain ACID requirements]
- Team expertise: [consider implementation team]
- Cost considerations: [compare hosting/licensing costs]
```

---

### Step 3: Design Core Schema

For each major entity group, design tables/collections:

#### A. Cloud Environment Schema

```sql
-- If using PostgreSQL, provide SQL DDL
-- If using NoSQL, provide JSON schema

CREATE TABLE cloud_providers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL, -- 'aws', 'gcp', 'azure'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id INTEGER REFERENCES cloud_providers(id),
    account_identifier VARCHAR(255) NOT NULL, -- AWS account ID, GCP project ID
    account_name VARCHAR(255),
    regions TEXT[], -- Array of enabled regions
    organization_id VARCHAR(255),
    environment VARCHAR(20) CHECK (environment IN ('prod', 'staging', 'dev')),
    criticality VARCHAR(20) CHECK (criticality IN ('high', 'medium', 'low')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_id, account_identifier)
);

CREATE INDEX idx_accounts_provider ON accounts(provider_id);
CREATE INDEX idx_accounts_org ON accounts(organization_id);

-- Continue for all cloud environment entities...
```

**Reasoning:**
- Why UUID for primary key? (distributed systems, no collisions)
- Why TEXT[] for regions? (variable number, PostgreSQL-specific)
- Why CHECK constraints? (data integrity at DB level)
- What indexes are needed? (based on query patterns)

---

#### B. Detection Schema

```sql
CREATE TABLE detection_services (
    id SERIAL PRIMARY KEY,
    provider_id INTEGER REFERENCES cloud_providers(id),
    service_name VARCHAR(100) NOT NULL, -- 'cloudwatch', 'guardduty', 'cloud_logging'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_id, service_name)
);

CREATE TABLE detection_types (
    id SERIAL PRIMARY KEY,
    type_name VARCHAR(50) UNIQUE NOT NULL, -- 'log_query', 'event_pattern', 'metric_alarm'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    service_id INTEGER REFERENCES detection_services(id),
    detection_type_id INTEGER REFERENCES detection_types(id),
    
    -- Core fields
    name VARCHAR(500),
    raw_config JSONB NOT NULL, -- Flexible storage for any detection format
    status VARCHAR(20) CHECK (status IN ('enabled', 'disabled', 'deprecated')),
    
    -- Metadata
    owner VARCHAR(255),
    tags TEXT[],
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Version tracking for drift detection
    version INTEGER DEFAULT 1,
    previous_version_id UUID REFERENCES detections(id)
);

CREATE INDEX idx_detections_account ON detections(account_id);
CREATE INDEX idx_detections_status ON detections(status);
CREATE INDEX idx_detections_service ON detections(service_id);
CREATE INDEX idx_detections_type ON detections(detection_type_id);
CREATE INDEX idx_detections_modified ON detections(last_modified);

-- Full-text search on names and tags (for user search)
CREATE INDEX idx_detections_search ON detections USING gin(to_tsvector('english', name));
```

**Reasoning:**
- Why JSONB for raw_config? (flexible, indexable, queryable)
- Why version tracking? (detect configuration changes for drift analysis)
- Why GIN index on name? (fast text search)
- Why CASCADE on account deletion? (data cleanup)

---

#### C. Parsed Detection Logic Schema

```sql
CREATE TABLE detection_logic (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES detections(id) ON DELETE CASCADE,
    
    -- Normalized detection logic
    monitored_entities JSONB, -- List of entities being monitored
    trigger_conditions JSONB, -- Conditions that trigger alert
    actions JSONB, -- What happens when triggered
    
    -- Metadata
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    false_positive_indicators TEXT[],
    
    -- Parsing metadata
    parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    parser_version VARCHAR(50),
    parse_confidence DECIMAL(3,2) CHECK (parse_confidence BETWEEN 0 AND 1),
    
    UNIQUE(detection_id)
);

CREATE INDEX idx_detection_logic_detection ON detection_logic(detection_id);
```

**Reasoning:**
- Why separate table? (not all detections parseable immediately)
- Why JSONB for logic? (flexible nested structures)
- Why parser_version? (track which parser version was used)

---

#### D. MITRE Framework Schema

```sql
CREATE TABLE mitre_versions (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) UNIQUE NOT NULL, -- 'v13.1', 'v14.0'
    release_date DATE,
    is_active BOOLEAN DEFAULT FALSE, -- Only one active version at a time
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE mitre_tactics (
    id SERIAL PRIMARY KEY,
    version_id INTEGER REFERENCES mitre_versions(id),
    tactic_id VARCHAR(20) NOT NULL, -- 'TA0001'
    name VARCHAR(255) NOT NULL, -- 'Initial Access'
    description TEXT,
    url VARCHAR(500),
    display_order INTEGER, -- For consistent UI ordering
    UNIQUE(version_id, tactic_id)
);

CREATE TABLE mitre_techniques (
    id SERIAL PRIMARY KEY,
    version_id INTEGER REFERENCES mitre_versions(id),
    technique_id VARCHAR(20) NOT NULL, -- 'T1078' or 'T1078.004'
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_technique_id VARCHAR(20), -- For sub-techniques
    platforms TEXT[], -- ['IaaS', 'Linux', 'Windows']
    data_sources TEXT[],
    detection_guidance TEXT,
    url VARCHAR(500),
    UNIQUE(version_id, technique_id)
);

CREATE INDEX idx_techniques_version ON mitre_techniques(version_id);
CREATE INDEX idx_techniques_parent ON mitre_techniques(parent_technique_id);
CREATE INDEX idx_techniques_platforms ON mitre_techniques USING gin(platforms);

-- Junction table: Techniques belong to multiple Tactics
CREATE TABLE technique_tactics (
    technique_id INTEGER REFERENCES mitre_techniques(id) ON DELETE CASCADE,
    tactic_id INTEGER REFERENCES mitre_tactics(id) ON DELETE CASCADE,
    PRIMARY KEY (technique_id, tactic_id)
);

CREATE TABLE threat_indicators (
    id SERIAL PRIMARY KEY,
    technique_id INTEGER REFERENCES mitre_techniques(id),
    provider_id INTEGER REFERENCES cloud_providers(id),
    
    indicator_type VARCHAR(50), -- 'api_call', 'log_pattern', 'metric_threshold'
    indicator_value TEXT, -- 'iam:AssumeRole', 'RunInstances'
    context_requirements JSONB, -- Additional conditions needed
    confidence DECIMAL(3,2) CHECK (confidence BETWEEN 0 AND 1),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_indicators_technique ON threat_indicators(technique_id);
CREATE INDEX idx_indicators_provider ON threat_indicators(provider_id);
CREATE INDEX idx_indicators_type ON threat_indicators(indicator_type);
```

**Reasoning:**
- Why version tracking? (MITRE updates 2x/year, must maintain history)
- Why is_active boolean? (only one active framework at a time)
- Why platforms array? (filter techniques by applicability)
- Why threat_indicators separate? (extensible, can add more over time)

---

#### E. Mapping Schema (M:N relationship core)

```sql
CREATE TABLE detection_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES detections(id) ON DELETE CASCADE,
    technique_id INTEGER REFERENCES mitre_techniques(id),
    
    -- Mapping metadata
    confidence_score DECIMAL(3,2) CHECK (confidence_score BETWEEN 0 AND 1),
    mapping_method VARCHAR(50) CHECK (mapping_method IN ('manual', 'pattern_match', 'nlp', 'ml_inference')),
    mapped_by VARCHAR(255), -- User ID or 'system'
    mapped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Validation
    validation_status VARCHAR(20) CHECK (validation_status IN ('validated', 'pending', 'disputed')),
    validated_by VARCHAR(255),
    validated_at TIMESTAMP,
    
    -- Explainability
    rationale TEXT,
    
    UNIQUE(detection_id, technique_id)
);

CREATE INDEX idx_mappings_detection ON detection_mappings(detection_id);
CREATE INDEX idx_mappings_technique ON detection_mappings(technique_id);
CREATE INDEX idx_mappings_confidence ON detection_mappings(confidence_score);
CREATE INDEX idx_mappings_method ON detection_mappings(mapping_method);

-- Composite index for common query: "What detections cover this technique?"
CREATE INDEX idx_mappings_technique_confidence ON detection_mappings(technique_id, confidence_score);
```

**Reasoning:**
- Why UNIQUE constraint? (prevent duplicate mappings)
- Why track mapping_method? (transparency, debugging, confidence calibration)
- Why validation_status? (human review loop)
- Why rationale field? (explainability for users)

---

#### F. Coverage Analysis Schema

```sql
CREATE TABLE coverage_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    tactic_id INTEGER REFERENCES mitre_tactics(id),
    
    -- Scores
    coverage_percentage DECIMAL(5,2), -- 0.00 to 100.00
    covered_techniques INTEGER,
    total_techniques INTEGER,
    
    -- Metadata
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    mitre_version_id INTEGER REFERENCES mitre_versions(id),
    
    -- For historical tracking
    UNIQUE(account_id, tactic_id, calculated_at)
);

CREATE INDEX idx_coverage_account ON coverage_scores(account_id);
CREATE INDEX idx_coverage_calculated ON coverage_scores(calculated_at);

CREATE TABLE coverage_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    technique_id INTEGER REFERENCES mitre_techniques(id),
    
    -- Gap analysis
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    risk_score DECIMAL(5,2), -- Calculated based on asset criticality + technique prevalence
    affected_assets JSONB, -- List of critical assets exposed
    
    -- Recommendations
    recommended_detections JSONB, -- List of detection templates
    business_impact TEXT,
    
    -- Status tracking
    status VARCHAR(20) CHECK (status IN ('open', 'acknowledged', 'remediated', 'accepted_risk')),
    first_identified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    
    UNIQUE(account_id, technique_id)
);

CREATE INDEX idx_gaps_account ON coverage_gaps(account_id);
CREATE INDEX idx_gaps_status ON coverage_gaps(status);
CREATE INDEX idx_gaps_severity ON coverage_gaps(severity);
CREATE INDEX idx_gaps_risk ON coverage_gaps(risk_score DESC);

CREATE TABLE coverage_overlaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    technique_id INTEGER REFERENCES mitre_techniques(id),
    
    detection_ids UUID[], -- Array of detection IDs
    redundancy_score DECIMAL(3,2),
    redundancy_type VARCHAR(20) CHECK (redundancy_type IN ('beneficial', 'excessive', 'conflicting')),
    recommendation TEXT,
    
    identified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(account_id, technique_id)
);

CREATE INDEX idx_overlaps_account ON coverage_overlaps(account_id);
```

**Reasoning:**
- Why separate coverage_scores table? (pre-computed for fast dashboard loading)
- Why UNIQUE on (account, tactic, calculated_at)? (time-series data)
- Why status tracking on gaps? (workflow management)
- Why risk_score? (prioritize gaps by actual risk)

---

#### G. Validation & Health Schema

```sql
CREATE TABLE detection_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES detections(id) ON DELETE CASCADE,
    
    -- Health status
    status VARCHAR(20) CHECK (status IN ('healthy', 'degraded', 'broken', 'unknown')),
    health_score DECIMAL(3,2) CHECK (health_score BETWEEN 0 AND 1),
    
    -- Validation details
    last_validated TIMESTAMP,
    validation_method VARCHAR(50) CHECK (validation_method IN ('syntax_check', 'semantic_check', 'test_trigger')),
    error_details TEXT,
    issues_found TEXT[],
    
    -- Trigger history
    last_triggered TIMESTAMP,
    trigger_count_30d INTEGER DEFAULT 0,
    
    -- API drift
    api_drift_detected BOOLEAN DEFAULT FALSE,
    deprecated_apis TEXT[],
    
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(detection_id)
);

CREATE INDEX idx_health_detection ON detection_health(detection_id);
CREATE INDEX idx_health_status ON detection_health(status);
CREATE INDEX idx_health_validated ON detection_health(last_validated);

CREATE TABLE api_deprecations (
    id SERIAL PRIMARY KEY,
    provider_id INTEGER REFERENCES cloud_providers(id),
    service VARCHAR(100),
    api_name VARCHAR(255),
    
    deprecation_date DATE,
    end_of_life_date DATE,
    replacement VARCHAR(255),
    announcement_url VARCHAR(500),
    migration_guidance TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(provider_id, service, api_name)
);

CREATE INDEX idx_deprecations_provider ON api_deprecations(provider_id);
CREATE INDEX idx_deprecations_eol ON api_deprecations(end_of_life_date);

-- Junction table: Which detections are affected by which deprecations
CREATE TABLE detection_deprecation_impact (
    detection_id UUID REFERENCES detections(id) ON DELETE CASCADE,
    deprecation_id INTEGER REFERENCES api_deprecations(id) ON DELETE CASCADE,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (detection_id, deprecation_id)
);
```

**Reasoning:**
- Why separate health table? (not all detections validated simultaneously)
- Why trigger history? (identify "dead" detections)
- Why junction table for deprecations? (M:N relationship)

---

#### H. Temporal/Historical Schema

```sql
CREATE TABLE scan_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    
    -- Snapshot metadata
    scan_started_at TIMESTAMP NOT NULL,
    scan_completed_at TIMESTAMP,
    scan_status VARCHAR(20) CHECK (scan_status IN ('in_progress', 'completed', 'failed', 'partial')),
    
    -- Summary statistics
    total_detections INTEGER,
    total_services_scanned INTEGER,
    total_regions_scanned INTEGER,
    
    -- For drift detection
    detections_added INTEGER DEFAULT 0,
    detections_removed INTEGER DEFAULT 0,
    detections_modified INTEGER DEFAULT 0,
    
    errors JSONB, -- Any errors encountered during scan
    
    UNIQUE(account_id, scan_started_at)
);

CREATE INDEX idx_snapshots_account ON scan_snapshots(account_id);
CREATE INDEX idx_snapshots_completed ON scan_snapshots(scan_completed_at);

-- Store actual snapshot data in S3/object storage, reference here
CREATE TABLE snapshot_storage (
    snapshot_id UUID PRIMARY KEY REFERENCES scan_snapshots(id) ON DELETE CASCADE,
    storage_location VARCHAR(500), -- S3 URI or file path
    compressed_size_bytes BIGINT,
    uncompressed_size_bytes BIGINT,
    checksum VARCHAR(64) -- SHA256 for integrity
);

CREATE TABLE coverage_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    technique_id INTEGER REFERENCES mitre_techniques(id),
    snapshot_id UUID REFERENCES scan_snapshots(id),
    
    detection_count INTEGER, -- How many detections covered this technique at this time
    coverage_score DECIMAL(3,2),
    
    timestamp TIMESTAMP NOT NULL,
    
    UNIQUE(account_id, technique_id, timestamp)
);

CREATE INDEX idx_coverage_history_account ON coverage_history(account_id);
CREATE INDEX idx_coverage_history_technique ON coverage_history(technique_id);
CREATE INDEX idx_coverage_history_time ON coverage_history(timestamp);
```

**Reasoning:**
- Why scan_snapshots? (track when scans occurred, detect drift)
- Why snapshot_storage separate? (large data offloaded to S3)
- Why coverage_history? (time-series for trend visualization)

---

### Step 4: Define Views for Common Queries

```sql
-- View: Current coverage status per account
CREATE VIEW v_account_coverage AS
SELECT 
    a.id AS account_id,
    a.account_name,
    COUNT(DISTINCT d.id) AS total_detections,
    COUNT(DISTINCT dm.technique_id) AS covered_techniques,
    (SELECT COUNT(*) FROM mitre_techniques WHERE version_id = (SELECT id FROM mitre_versions WHERE is_active = TRUE)) AS total_techniques,
    ROUND(
        (COUNT(DISTINCT dm.technique_id)::DECIMAL / 
         (SELECT COUNT(*) FROM mitre_techniques WHERE version_id = (SELECT id FROM mitre_versions WHERE is_active = TRUE))
        ) * 100, 
        2
    ) AS coverage_percentage
FROM accounts a
LEFT JOIN detections d ON a.id = d.account_id AND d.status = 'enabled'
LEFT JOIN detection_mappings dm ON d.id = dm.detection_id AND dm.confidence_score >= 0.6
GROUP BY a.id, a.account_name;

-- View: Techniques without coverage per account (gaps)
CREATE VIEW v_coverage_gaps_current AS
SELECT 
    a.id AS account_id,
    mt.technique_id,
    mt.name AS technique_name,
    mt.description,
    COUNT(dm.id) AS detection_count
FROM accounts a
CROSS JOIN mitre_techniques mt
LEFT JOIN detection_mappings dm ON mt.id = dm.technique_id 
    AND dm.detection_id IN (
        SELECT id FROM detections WHERE account_id = a.id AND status = 'enabled'
    )
WHERE mt.version_id = (SELECT id FROM mitre_versions WHERE is_active = TRUE)
GROUP BY a.id, mt.id, mt.technique_id, mt.name, mt.description
HAVING COUNT(dm.id) = 0;

-- View: Detection health summary
CREATE VIEW v_detection_health_summary AS
SELECT 
    a.id AS account_id,
    a.account_name,
    COUNT(CASE WHEN dh.status = 'healthy' THEN 1 END) AS healthy_detections,
    COUNT(CASE WHEN dh.status = 'degraded' THEN 1 END) AS degraded_detections,
    COUNT(CASE WHEN dh.status = 'broken' THEN 1 END) AS broken_detections,
    COUNT(CASE WHEN dh.status = 'unknown' THEN 1 END) AS unknown_detections,
    COUNT(CASE WHEN dh.api_drift_detected = TRUE THEN 1 END) AS detections_with_drift
FROM accounts a
JOIN detections d ON a.id = d.account_id
LEFT JOIN detection_health dh ON d.id = dh.detection_id
GROUP BY a.id, a.account_name;
```

**Reasoning:**
- Why views? (simplify complex queries, reusable)
- Why confidence_score >= 0.6 filter? (only count reliable mappings)
- Why status = 'enabled' filter? (disabled detections don't provide coverage)

---

### Step 5: Data Migration & Versioning Strategy

**Schema Evolution Plan:**

```sql
-- Use migration tool (Alembic for Python, Flyway for Java, etc.)

-- Version 1: Initial schema
-- migrations/001_initial_schema.sql

-- Version 2: Add NLP mapping support
-- migrations/002_add_nlp_fields.sql
ALTER TABLE detection_mappings ADD COLUMN nlp_confidence DECIMAL(3,2);
ALTER TABLE detection_logic ADD COLUMN nlp_extracted_intent TEXT;

-- Version 3: Add GCP support
-- migrations/003_add_gcp_support.sql
INSERT INTO cloud_providers (name) VALUES ('gcp');
-- Add GCP-specific services...

-- Version 4: Performance optimization
-- migrations/004_add_indexes.sql
CREATE INDEX idx_detections_account_status ON detections(account_id, status);
```

**Migration Best Practices:**
1. Always backward compatible (no data loss)
2. Version every migration
3. Test migrations on copy of production data
4. Provide rollback scripts
5. Document breaking changes

---

### Step 6: Data Integrity & Constraints

**Additional Constraints to Consider:**

```sql
-- Ensure coverage scores are calculated with current MITRE version
ALTER TABLE coverage_scores ADD CONSTRAINT fk_active_mitre_version
    FOREIGN KEY (mitre_version_id) 
    REFERENCES mitre_versions(id);

-- Ensure detection health is recent (alert if stale)
CREATE OR REPLACE FUNCTION check_health_staleness() RETURNS TRIGGER AS $$
BEGIN
    IF (CURRENT_TIMESTAMP - NEW.last_validated > INTERVAL '30 days') THEN
        RAISE WARNING 'Detection health is stale: % days old', 
            EXTRACT(DAY FROM (CURRENT_TIMESTAMP - NEW.last_validated));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_check_health_staleness
    BEFORE INSERT OR UPDATE ON detection_health
    FOR EACH ROW
    EXECUTE FUNCTION check_health_staleness();

-- Ensure only one active MITRE version
CREATE UNIQUE INDEX idx_single_active_mitre ON mitre_versions(is_active) 
    WHERE is_active = TRUE;
```

---

### Step 7: Performance Optimization

**Indexing Strategy:**
```sql
-- Composite indexes for common query patterns

-- Query: "Show all detections for this account with mapping confidence > X"
CREATE INDEX idx_detections_account_mappings 
    ON detections(account_id, status) 
    INCLUDE (id, name, created_at);

-- Query: "What techniques are covered by this account?"
CREATE INDEX idx_mappings_coverage 
    ON detection_mappings(technique_id, confidence_score) 
    WHERE confidence_score >= 0.6;

-- Query: "Historical coverage trend for technique T1078"
CREATE INDEX idx_coverage_history_trend 
    ON coverage_history(technique_id, timestamp DESC);
```

**Partitioning Strategy (for large-scale):**
```sql
-- Partition scan_snapshots by time (monthly)
CREATE TABLE scan_snapshots_2024_01 PARTITION OF scan_snapshots
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Partition detection_mappings by account (if 10000+ accounts)
CREATE TABLE detection_mappings_account_1 PARTITION OF detection_mappings
    FOR VALUES IN (account_id_1, account_id_2, ...);
```

---

## Output Artifacts

### 1. Complete SQL Schema
**File:** `schema/database-schema-v1.sql`

Provide the complete, runnable SQL that creates:
- All tables
- All indexes
- All constraints
- All views
- Sample trigger functions

### 2. Entity-Relationship Diagram
**File:** `docs/er-diagram.md` or `docs/er-diagram.png`

Visualize:
- All entities as boxes
- Relationships as lines (1:1, 1:M, M:N)
- Key fields listed
- Cardinality noted

**Tools:** Draw.io, Mermaid, dbdiagram.io

### 3. Data Dictionary
**File:** `docs/data-dictionary.md`

For each table, document:
- Purpose
- Key fields and their meaning
- Relationships to other tables
- Expected volume (small, medium, large)
- Access patterns (read-heavy, write-heavy)

### 4. Query Patterns Document
**File:** `docs/query-patterns.md`

List 20-30 most common queries with:
- Query description
- SQL example
- Expected execution time
- Indexes used

Example:
```
Query: Get all coverage gaps for account X sorted by risk
SQL: SELECT * FROM coverage_gaps WHERE account_id = ? AND status = 'open' ORDER BY risk_score DESC
Indexes Used: idx_gaps_account, idx_gaps_risk
Expected Time: < 50ms
```

### 5. Migration Plan
**File:** `docs/migration-strategy.md`

Document:
- Migration tool choice (Alembic, Flyway, etc.)
- Migration workflow
- Rollback strategy
- Testing approach

---

## Validation Checklist

Before declaring the data model complete, verify:

**Completeness:**
- [ ] All entities from formal model are represented
- [ ] All relationships are defined
- [ ] All state variables have storage
- [ ] Historical data is tracked (snapshots, versions)

**Performance:**
- [ ] Indexes cover common query patterns
- [ ] Partitioning strategy for large tables
- [ ] Views simplify complex queries
- [ ] N+1 query problems are avoided

**Integrity:**
- [ ] Foreign keys enforce relationships
- [ ] CHECK constraints validate data
- [ ] UNIQUE constraints prevent duplicates
- [ ] Cascading deletes are appropriate

**Scalability:**
- [ ] Schema handles 1000+ accounts
- [ ] Schema handles 1M+ detections
- [ ] Schema handles 100k+ techniques (MITRE versions)
- [ ] Time-series data growth is managed

**Maintainability:**
- [ ] Clear naming conventions
- [ ] Well-documented schema
- [ ] Migration strategy defined
- [ ] Backward compatibility considered

---

## Open Questions for Orchestrator

Flag these issues back to the orchestrator:

1. **Database Technology**: Confirm PostgreSQL vs. other options
2. **Temporal Data Retention**: How long to keep historical snapshots? (30 days? 1 year?)
3. **Soft Deletes**: Should we soft-delete or hard-delete? (audit trail vs. data cleanup)
4. **Multi-Tenancy**: Is this single-tenant or multi-tenant SaaS? (impacts account isolation)
5. **Backup Strategy**: RDS automated backups? Point-in-time recovery needed?

---

## Next Agent

Once data model is validated, proceed to:
**→ 02-API-DESIGN-AGENT.md**

Provide the API agent with:
- Completed database schema
- List of entities and their key fields
- Common query patterns

The API agent will design RESTful endpoints that map to database operations.

---

**END OF DATA MODEL AGENT**
