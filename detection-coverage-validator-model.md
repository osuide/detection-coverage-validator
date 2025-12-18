# Detection Coverage Validator - Formal Problem Model

## Project Overview

A multi-cloud security detection coverage analysis system that provides visibility into MITRE ATT&CK coverage across AWS and GCP environments, identifies gaps, validates detection health, and recommends remediation.

---

## Implementation Phases (Added 2025-12-18)

> **IMPORTANT:** This section maps the problem model to implementation phases.
> See `ROADMAP.md` for detailed implementation plan.

### Phase 0: MVP Launch (CURRENT FOCUS)
**Goal:** Revenue-generating product with core value

| Feature | Status | Notes |
|---------|--------|-------|
| AWS Scanning (CloudWatch, EventBridge, GuardDuty) | ✅ Done | Pattern-based mapping |
| MITRE Mapping (Pattern Matching) | ✅ Done | 80%+ coverage |
| Coverage Calculation | ✅ Done | Per-tactic/technique |
| Gap Identification | ✅ Done | Risk prioritization |
| Basic Dashboard | ✅ Done | Heatmap, metrics |
| **Stripe Integration** | ⏳ TODO | CRITICAL |
| **Staging Environment** | ⏳ TODO | CRITICAL |
| **Real AWS Scanning** | ⏳ TODO | Remove dev mode |
| OAuth Login | ⏳ TODO | Google, GitHub |
| Email Service | ⏳ TODO | Password reset |

### Phase 1: Post-Launch (After revenue)
| Feature | Model Section | Notes |
|---------|---------------|-------|
| Detection Validation | Section 3D (ValidateDetection) | Syntax + Semantic |
| Scheduled Scans | Section 3A (ScanAccount) | Background jobs |
| Drift Detection | Section 3C (IdentifyDrift) | Historical comparison |
| GCP Full Support | Section 1A (DetectionService) | Currently partial |

### Phase 2: Advanced (1-2 months)
| Feature | Model Section | Notes |
|---------|---------------|-------|
| NLP-Based Mapping | Section 3B (AutoMapDetections) | For custom code |
| Detection Recommendations | Section 3E (RecommendDetection) | Actionable gaps |
| MITRE Navigator Export | Section 3C (CalculateCoverage) | JSON export |

### Phase 3: Enterprise (3-6 months)
| Feature | Model Section | Notes |
|---------|---------------|-------|
| IaC Generation | Section 3E (GenerateIaC) | Terraform/CFN |
| ML-Based Mapping | Section 3B (AutoMapDetections) | Classification model |
| API Deprecation Monitoring | Section 3D (MonitorAPIDeprecations) | Proactive health |
| SIEM Integration | N/A - new requirement | Splunk, Elastic |

### Deferred Indefinitely
| Feature | Reason |
|---------|--------|
| Azure Support | Focus on AWS/GCP first |
| Custom Compliance Frameworks | Enterprise feature |
| White-labeling | Enterprise feature |

---

## 1. ENTITIES (Core Domain Objects)

### A. Cloud Environment Entities

#### CloudProvider
- **Type**: Enumeration
- **Values**: `{AWS, GCP, Azure...}`
- **Purpose**: Identify which cloud platform is being analyzed

#### Account
- **Description**: Cloud account/project with unique identifier
- **Attributes**:
  - `provider`: CloudProvider
  - `account_id`: String (unique per provider)
  - `name`: String
  - `regions`: List[String] (AWS regions or GCP zones)
  - `organization_id`: Optional[String]
  - `environment`: Enum {prod, staging, dev}
  - `criticality`: Enum {high, medium, low}

#### DetectionService
- **Description**: Native security/monitoring service provided by cloud vendor
- **AWS Services**:
  - CloudWatch (Logs, Metrics, Alarms)
  - GuardDuty
  - EventBridge
  - AWS Config
  - Security Hub
  - Lambda (custom detection functions)
- **GCP Services**:
  - Cloud Logging
  - Security Command Center
  - Eventarc
  - Cloud Monitoring
  - Cloud Functions (custom detection functions)
  - Cloud Asset Inventory

#### CloudAsset
- **Description**: Resources being monitored within cloud environment
- **Attributes**:
  - `asset_type`: String (EC2, GCS, IAM, RDS, etc.)
  - `asset_id`: String
  - `region`: String
  - `tags`: Map[String, String]
  - `criticality`: Enum {high, medium, low}
  - `data_classification`: Enum {public, internal, confidential, restricted}

---

### B. Detection Entities

#### Detection
- **Description**: Single detection rule/query/pattern deployed in cloud environment
- **Attributes**:
  - `id`: String (unique identifier)
  - `name`: String
  - `source_service`: DetectionService
  - `detection_type`: DetectionType
  - `raw_config`: JSON/YAML (original configuration)
  - `status`: Enum {enabled, disabled, deprecated}
  - `created_date`: Timestamp
  - `last_modified`: Timestamp
  - `owner`: String (team/person responsible)
  - `tags`: List[String]

#### DetectionType
- **Type**: Enumeration
- **Values**:
  - `LogQuery`: Searches through log data (CloudWatch Logs Insights, Cloud Logging)
  - `EventPattern`: Matches specific event patterns (EventBridge, Eventarc)
  - `MetricAlarm`: Triggers on metric thresholds (CloudWatch Alarms, Cloud Monitoring)
  - `ConfigRule`: Validates resource configurations (AWS Config, Cloud Asset)
  - `CustomFunction`: Code-based detection logic (Lambda, Cloud Functions)
  - `ManagedDetection`: Vendor-provided detection (GuardDuty, Security Command Center)

#### DetectionLogic
- **Description**: Parsed and normalized intent extracted from raw configuration
- **Attributes**:
  - `monitored_entities`: List[String] (what is being watched)
  - `trigger_conditions`: List[Condition] (what makes it fire)
  - `actions`: List[Action] (what happens when triggered)
  - `severity`: Enum {critical, high, medium, low, info}
  - `false_positive_indicators`: List[String]
  - `filter_logic`: NormalizedExpression

---

### C. Threat Model Entities

#### MITRETactic
- **Description**: High-level attack goal from MITRE ATT&CK framework
- **Attributes**:
  - `tactic_id`: String (TA0001-TA0011)
  - `name`: String (e.g., "Initial Access", "Execution", "Persistence")
  - `description`: String
  - `url`: String (MITRE documentation link)
- **Complete List**:
  1. TA0001 - Initial Access
  2. TA0002 - Execution
  3. TA0003 - Persistence
  4. TA0004 - Privilege Escalation
  5. TA0005 - Defense Evasion
  6. TA0006 - Credential Access
  7. TA0007 - Discovery
  8. TA0008 - Lateral Movement
  9. TA0009 - Collection
  10. TA0010 - Exfiltration
  11. TA0011 - Command and Control
  12. TA0040 - Impact

#### MITRETechnique
- **Description**: Specific attack method within a tactic
- **Attributes**:
  - `technique_id`: String (T####, T####.###)
  - `name`: String
  - `description`: String
  - `tactics`: List[MITRETactic] (many-to-many relationship)
  - `sub_techniques`: List[MITRETechnique]
  - `platforms`: List[String] (IaaS, SaaS, Linux, Windows, etc.)
  - `data_sources`: List[String]
  - `detection_guidance`: String
  - `url`: String

#### ThreatIndicator
- **Description**: Observable pattern that signals potential use of a technique
- **Attributes**:
  - `indicator_type`: Enum {API_call, log_pattern, metric_threshold, behavioral}
  - `cloud_provider`: CloudProvider
  - `indicator_value`: String (e.g., "iam:AssumeRole", "RunInstances")
  - `context_requirements`: List[String] (conditions that must also be present)
  - `confidence`: Float [0.0-1.0]

---

### D. Mapping Entities

#### DetectionMapping
- **Description**: Links a detection to one or more MITRE techniques it covers
- **Attributes**:
  - `detection_id`: String
  - `technique_ids`: List[String] (many-to-many)
  - `confidence_score`: Float [0.0-1.0]
  - `mapping_method`: Enum {manual, pattern_match, nlp, ml_inference}
  - `mapped_by`: String (human or algorithm version)
  - `mapped_date`: Timestamp
  - `validation_status`: Enum {validated, pending, disputed}
  - `rationale`: String (why this mapping exists)

#### CoverageGap
- **Description**: Identified lack of detection for a specific technique
- **Attributes**:
  - `technique_id`: String
  - `account_id`: String
  - `severity`: Enum {critical, high, medium, low}
  - `affected_assets`: List[CloudAsset]
  - `risk_score`: Float (based on asset criticality + technique prevalence)
  - `recommended_detections`: List[String] (detection IDs or templates)
  - `business_impact`: String
  - `first_identified`: Timestamp
  - `status`: Enum {open, acknowledged, remediated, accepted_risk}

#### CoverageOverlap
- **Description**: Multiple detections covering the same technique (redundancy analysis)
- **Attributes**:
  - `technique_id`: String
  - `account_id`: String
  - `detection_ids`: List[String]
  - `redundancy_score`: Float (measure of overlap)
  - `redundancy_type`: Enum {beneficial, excessive, conflicting}
  - `recommendation`: String (keep all, consolidate, etc.)

---

### E. Validation Entities

#### DetectionHealth
- **Description**: Current operational status of a detection
- **Attributes**:
  - `detection_id`: String
  - `last_validated`: Timestamp
  - `status`: Enum {healthy, degraded, broken, unknown}
  - `health_score`: Float [0.0-1.0]
  - `error_details`: Optional[String]
  - `validation_method`: Enum {syntax_check, semantic_check, test_trigger}
  - `issues_found`: List[String]
  - `last_triggered`: Optional[Timestamp] (when detection actually fired)

#### APIDeprecation
- **Description**: Cloud provider API or service changes that affect detections
- **Attributes**:
  - `provider`: CloudProvider
  - `service`: String
  - `api_name`: String
  - `deprecation_date`: Timestamp
  - `end_of_life_date`: Timestamp
  - `replacement`: Optional[String]
  - `affected_detections`: List[String] (detection IDs)
  - `migration_guidance`: String
  - `announcement_url`: String

---

## 2. STATE VARIABLES (What Changes Over Time)

### A. Detection State

#### detections_inventory
- **Type**: `Map[account_id → Set[Detection]]`
- **Description**: Complete inventory of all detections per account
- **Mutability**: Updated on each scan
- **Size**: 10s to 1000s of detections per account

#### detection_status
- **Type**: `Map[detection_id → Enum{enabled, disabled, deprecated}]`
- **Description**: Current operational status of each detection
- **Mutability**: Changes when detections are enabled/disabled/removed
- **Update Frequency**: Per scan (daily/weekly)

#### detection_config
- **Type**: `Map[detection_id → JSON]`
- **Description**: Raw configuration for each detection
- **Mutability**: Changes when detection rules are modified
- **Versioning**: Should track history for drift detection

#### detection_last_triggered
- **Type**: `Map[detection_id → Optional[Timestamp]]`
- **Description**: Last time each detection actually fired an alert
- **Purpose**: Identify "dead" detections that never trigger
- **Source**: Must be pulled from SIEM/alerting system if available

---

### B. Mapping State

#### coverage_map
- **Type**: `Map[account_id → Map[technique_id → Set[detection_id]]]`
- **Description**: Which detections cover which techniques for each account
- **Mutability**: Updated when new mappings are created or detections change
- **Query Pattern**: "Show all detections for technique T1078"

#### mapping_confidence
- **Type**: `Map[detection_id → Map[technique_id → Float]]`
- **Description**: Confidence score [0.0-1.0] for each detection-technique mapping
- **Purpose**: Distinguish high-confidence vs. uncertain mappings
- **Update**: Increases with validation, decreases with age/drift

#### unmapped_detections
- **Type**: `Map[account_id → Set[detection_id]]`
- **Description**: Detections that couldn't be mapped to any MITRE technique
- **Causes**: Complex custom logic, unparseable config, no matching indicators
- **Action**: Requires manual review or improved parsing

#### coverage_score
- **Type**: `Map[account_id → Map[tactic_id → Float]]`
- **Description**: Percentage coverage for each tactic (0-100%)
- **Calculation**: `(covered_techniques / total_applicable_techniques) * 100`
- **Aggregation**: Can roll up to overall account score

---

### C. Gap State

#### identified_gaps
- **Type**: `Map[account_id → Set[CoverageGap]]`
- **Description**: All techniques with zero or inadequate coverage
- **Priority**: Sorted by risk_score
- **Filtering**: Can filter by tactic, asset type, severity

#### single_point_failures
- **Type**: `Map[account_id → Map[technique_id → detection_id]]`
- **Description**: Techniques covered by exactly one detection (no redundancy)
- **Risk**: If that detection breaks, coverage is lost
- **Recommendation**: Add redundant detection for critical techniques

#### coverage_drift
- **Type**: `Map[account_id → List[DriftEvent]]`
- **DriftEvent**: `{technique_id, lost_detections[], timestamp, cause}`
- **Description**: Techniques that lost coverage over time
- **Causes**: Detections disabled, deleted, deprecated, or broken

---

### D. Validation State

#### detection_health
- **Type**: `Map[detection_id → DetectionHealth]`
- **Description**: Health status of each detection
- **Update Frequency**: On-demand or scheduled (daily/weekly)
- **Alerts**: Generate alert when health degrades

#### validation_timestamp
- **Type**: `Map[detection_id → Timestamp]`
- **Description**: Last time each detection was validated
- **Staleness Threshold**: Flag if > 30 days old
- **Purpose**: Know which detections need re-validation

#### api_drift_detected
- **Type**: `Map[detection_id → Boolean]`
- **Description**: Whether detection references deprecated/changed APIs
- **Source**: Cross-reference with APIDeprecation entities
- **Action**: Requires detection update to use new API

#### false_positive_rate
- **Type**: `Map[detection_id → Optional[Float]]`
- **Description**: Estimated false positive rate if known
- **Source**: SIEM/alerting system metrics (if available)
- **Use**: Inform coverage quality assessment

---

### E. Temporal State

#### scan_history
- **Type**: `Map[account_id → List[ScanSnapshot]]`
- **ScanSnapshot**: `{timestamp, detections_inventory, coverage_map}`
- **Description**: Point-in-time snapshots for trend analysis
- **Retention**: Keep last N snapshots (e.g., 90 days)
- **Purpose**: Enable drift detection and historical analysis

#### coverage_history
- **Type**: `Map[account_id → Map[technique_id → TimeSeries[Float]]]`
- **Description**: Coverage score over time for each technique
- **Visualization**: Line charts showing coverage trends
- **Alerts**: Detect sudden drops in coverage

#### mitre_version
- **Type**: `String` (e.g., "v13.1")
- **Description**: Current MITRE ATT&CK framework version in use
- **Update Frequency**: MITRE releases ~2x per year
- **Migration**: Requires remapping when version changes

---

## 3. POSSIBLE ACTIONS (with Preconditions & Effects)

### A. INGESTION ACTIONS

#### Action: ScanAccount
```
ScanAccount(account_id, provider, credentials)
```

**Purpose**: Discover and ingest all detection configurations from a cloud account

**Preconditions**:
- Valid credentials exist for the account
- Account is accessible (not suspended/deleted)
- Provider SDK is available (boto3 for AWS, google-cloud-python for GCP)
- Required IAM permissions granted (read-only)
- API rate limits not exceeded

**Effects**:
- `detections_inventory[account_id]` populated with discovered detections
- `detection_status[detection_id]` initialized for each detection
- `scan_history[account_id]` appended with new snapshot
- Metadata collected: last_modified dates, owners, tags

**Side Effects**:
- API rate limit consumption (100s of API calls)
- Temporary credentials may be cached (security consideration)
- Logging of scan activity (audit trail)

**Failure Modes**:
- Permission denied (insufficient IAM permissions)
- Rate limiting (429 errors)
- Timeout (large accounts with many resources)
- Partial failure (some services accessible, others not)

**AWS-Specific Services to Scan**:
- CloudWatch: Metric Filters, Alarms, Logs Insights saved queries
- EventBridge: Rules with patterns
- AWS Config: Rules (managed and custom)
- GuardDuty: Detector settings, suppression rules
- Security Hub: Custom insights and actions
- Lambda: Functions with event triggers (potential custom detections)

**GCP-Specific Services to Scan**:
- Cloud Logging: Log-based metrics, saved queries
- Cloud Monitoring: Alerting policies
- Security Command Center: Notification configs, custom modules
- Eventarc: Triggers
- Cloud Functions: Functions with event triggers

---

#### Action: ParseDetection
```
ParseDetection(detection_id)
```

**Purpose**: Extract detection logic from raw configuration into structured format

**Preconditions**:
- Detection exists in `detections_inventory`
- Parser available for the detection's `detection_type`
- Raw configuration is valid (not corrupted)

**Effects**:
- `DetectionLogic` object created for the detection
- Monitored entities identified
- Trigger conditions extracted
- Actions/severity parsed

**Challenges**:
- Complex query languages (CloudWatch Logs Insights syntax, GCP Logging query syntax)
- Nested conditional logic (if/else/and/or)
- References to external resources (log groups, SNS topics)
- Custom Lambda/Cloud Function code (black box)
- Vendor-specific functions and operators

**Failure Modes**:
- Unparseable syntax (edge cases in query language)
- Ambiguous logic (multiple interpretations possible)
- Incomplete configuration (references missing resources)
- Obfuscated code (intentionally complex)

**Parsing Strategies**:
- **Pattern Matching**: Regex-based extraction for simple patterns
- **AST Parsing**: Build abstract syntax tree for query languages
- **NLP**: Extract intent from human-readable descriptions
- **Static Analysis**: Analyze custom code (limited depth)
- **Fallback**: Mark as unparseable, require manual review

---

#### Action: NormalizeDetection
```
NormalizeDetection(detection_id)
```

**Purpose**: Convert cloud-specific detection logic to provider-agnostic format

**Preconditions**:
- Detection has been parsed successfully
- Normalization schema defined

**Effects**:
- Cloud-agnostic `DetectionLogic` representation created
- Detection is comparable across AWS/GCP/Azure
- Enables unified mapping to MITRE techniques

**Normalization Schema Example**:
```json
{
  "monitored_event": "authentication_attempt",
  "conditions": {
    "result": "failure",
    "count": ">= 5",
    "time_window": "5 minutes"
  },
  "target": "iam_user"
}
```

**Challenges**:
- Semantic equivalence is ambiguous (AWS "AssumeRole" ≈ GCP "serviceAccounts.actAs")
- Different granularity (one provider's single event = multiple in another)
- Provider-specific features (no direct equivalent)
- Loss of information (normalization = abstraction = information loss)

**Strategies**:
- Maintain mappings of equivalent APIs/events
- Preserve provider-specific details in metadata
- Flag when normalization is imperfect/uncertain
- Version the normalization schema (evolves over time)

---

### B. MAPPING ACTIONS

#### Action: MapDetectionToTechnique
```
MapDetectionToTechnique(detection_id, technique_id, confidence, method)
```

**Purpose**: Create explicit link between a detection and a MITRE technique

**Preconditions**:
- Detection logic has been extracted (parsed/normalized)
- `technique_id` exists in current MITRE ATT&CK framework
- Confidence score is justified by mapping method

**Effects**:
- `DetectionMapping` entity created
- `coverage_map[account_id][technique_id]` updated to include detection
- `mapping_confidence[detection_id][technique_id]` set
- If first mapping for technique, removed from `identified_gaps`

**Parameters**:
- `confidence`: Float [0.0-1.0]
  - 1.0: Manual verification by expert
  - 0.9: High-confidence pattern match
  - 0.7: NLP-based inference
  - 0.5: Low-confidence ML prediction
  - < 0.5: Requires manual review
- `method`: Enum {manual, pattern_match, nlp, ml_inference}

**Constraints**:
- One detection may map to multiple techniques (M:N relationship)
- Mapping must be explainable (no black box mappings)
- Low-confidence mappings should be flagged for review

**Examples**:

**Example 1: AWS CloudWatch Logs**
```
Detection: Log query for "eventName = AssumeRole AND errorCode exists"
Maps to: T1078.004 (Valid Accounts: Cloud Accounts)
Confidence: 0.9 (high-confidence pattern match)
Rationale: Failed AssumeRole attempts indicate credential validation
```

**Example 2: GCP Cloud Logging**
```
Detection: "protoPayload.methodName = iam.serviceAccounts.actAs"
Maps to: T1078.004 (Valid Accounts: Cloud Accounts)
Confidence: 0.9
Rationale: Service account impersonation = cloud account usage
```

**Example 3: Multi-Technique Mapping**
```
Detection: Lambda function monitoring EC2 instance launch in unusual region
Maps to:
  - T1578.002 (Create Cloud Instance) - confidence: 0.95
  - T1535 (Unused/Unsupported Cloud Regions) - confidence: 0.85
Rationale: Detects both instance creation AND region anomaly
```

---

#### Action: AutoMapDetections
```
AutoMapDetections(account_id, algorithm, confidence_threshold)
```

**Purpose**: Bulk mapping of all detections to MITRE techniques using automated methods

**Preconditions**:
- Detections have been parsed and normalized
- Mapping algorithm is available and trained (if ML-based)
- MITRE ATT&CK framework loaded

**Effects**:
- Multiple `DetectionMapping` entities created
- `coverage_map` populated across all techniques
- `unmapped_detections[account_id]` reduced (but not necessarily to zero)
- `coverage_score` can now be calculated

**Algorithm Options**:

**1. Pattern Matching**
- Match detection indicators (API calls, log patterns) to known technique signatures
- Pros: Fast, deterministic, explainable
- Cons: Limited to known patterns, misses novel detections
- Confidence: 0.8-0.9 for matches

**2. NLP-Based**
- Extract intent from detection names/descriptions using NLP
- Compare to MITRE technique descriptions (semantic similarity)
- Pros: Handles custom detections, flexible
- Cons: Requires good descriptions, lower confidence
- Confidence: 0.6-0.8

**3. ML Inference**
- Train classifier on labeled detection-technique pairs
- Features: API calls, conditions, severity, context
- Pros: Can learn complex patterns
- Cons: Requires training data, black box, lower confidence
- Confidence: 0.5-0.7

**4. Hybrid Approach**
- Pattern matching first (high confidence)
- NLP for remainder
- ML for still-unmapped
- Pros: Maximizes coverage and confidence
- Cons: Complex pipeline

**Quality Assurance**:
- Set `confidence_threshold` (e.g., 0.6): only create mappings above threshold
- Flag low-confidence mappings for manual review
- Track unmapped detections for gap analysis
- Provide explainability: why was this mapping made?

**Performance Considerations**:
- Large accounts may have 1000+ detections
- Batch processing required
- Caching of MITRE technique embeddings (for NLP)
- Incremental mapping (only new/changed detections)

---

### C. ANALYSIS ACTIONS

#### Action: CalculateCoverage
```
CalculateCoverage(account_id, scope)
```

**Purpose**: Compute coverage metrics across MITRE ATT&CK framework

**Preconditions**:
- Detections have been mapped to techniques
- `coverage_map[account_id]` populated

**Parameters**:
- `scope`: Enum {all, tactic, technique, asset_specific}
  - `all`: Overall coverage score
  - `tactic`: Per-tactic breakdown
  - `technique`: Per-technique detail
  - `asset_specific`: Coverage for specific critical assets

**Effects**:
- `coverage_score[account_id][tactic_id]` computed for each tactic
- `identified_gaps[account_id]` populated with zero-coverage techniques
- `single_point_failures[account_id]` identified (techniques with only 1 detection)
- `CoverageOverlap` entities created for techniques with 3+ detections

**Calculation Methods**:

**1. Simple Coverage Percentage**
```
coverage_score[tactic] = (covered_techniques / total_techniques) * 100
```

**2. Weighted Coverage**
```
coverage_score[tactic] = Σ(technique_coverage * technique_weight) / Σ(technique_weight)

Where:
  technique_coverage = min(detection_count, 3) / 3  # Cap at 3 detections
  technique_weight = technique_prevalence * asset_criticality
```

**3. Confidence-Adjusted Coverage**
```
technique_coverage = max(mapping_confidence for all detections covering technique)
```

**Outputs**:
- Overall coverage score: Float [0-100%]
- Per-tactic coverage: Map[tactic_id → Float]
- Per-technique status: Map[technique_id → Enum{covered, partial, none}]
- Gap list: List[CoverageGap] sorted by risk
- Redundancy analysis: List[CoverageOverlap]

**Visualization Formats**:
- MITRE Navigator heatmap JSON
- Tabular report (CSV/Excel)
- Executive summary (PDF)
- Dashboard metrics (Grafana/similar)

---

#### Action: IdentifyDrift
```
IdentifyDrift(account_id, time_window)
```

**Purpose**: Detect changes in coverage over time (regressions or improvements)

**Preconditions**:
- Historical scan data exists (`scan_history[account_id]`)
- At least 2 snapshots within `time_window`

**Parameters**:
- `time_window`: Duration (e.g., "30 days", "90 days")

**Effects**:
- `coverage_drift[account_id]` populated with drift events
- `detection_health` updated for removed/disabled detections
- Alerts generated for significant coverage loss

**Drift Detection Logic**:

**1. Detection-Level Drift**
```
For each detection in previous_snapshot:
  If detection not in current_snapshot:
    → Drift event: "Detection removed/deleted"
  Else if detection.status changed from enabled → disabled:
    → Drift event: "Detection disabled"
  Else if detection.config changed:
    → Drift event: "Detection modified" (may affect coverage)
```

**2. Coverage-Level Drift**
```
For each technique:
  previous_coverage = len(coverage_map[previous][technique])
  current_coverage = len(coverage_map[current][technique])
  
  If current_coverage < previous_coverage:
    → Drift event: "Coverage decreased"
    → Identify which detections were lost
  
  If previous_coverage > 0 AND current_coverage == 0:
    → Drift event: "Coverage completely lost" (CRITICAL)
```

**3. Health-Based Drift**
```
For each detection:
  If previous.health == "healthy" AND current.health == "broken":
    → Drift event: "Detection degraded"
    → Affects coverage for mapped techniques
```

**Drift Severity**:
- **Critical**: Complete coverage loss for high-severity technique
- **High**: Coverage reduced from 3+ → 1 detection
- **Medium**: Coverage reduced but still redundant
- **Low**: Detection modified but coverage unchanged

**Actionable Insights**:
- "Technique T1078 lost coverage on 2024-12-01 due to deletion of CloudWatch alarm 'failed-login-alert'"
- "5 detections disabled in the past 30 days, affecting coverage for 3 techniques"
- "Detection 'unusual-api-calls' was modified on 2024-11-15 and now triggers less frequently"

---

#### Action: AssessCoverageQuality
```
AssessCoverageQuality(account_id)
```

**Purpose**: Evaluate not just coverage quantity but also quality

**Preconditions**:
- Coverage has been calculated
- Asset inventory available
- (Optional) Detection trigger history available

**Effects**:
- Risk score per asset based on coverage gaps
- Critical gaps highlighted (high-value assets + zero coverage)
- Quality metrics per detection (FP rate, last triggered)

**Quality Factors**:

**1. Asset-Based Risk**
```
For each asset:
  relevant_techniques = MITRE techniques applicable to asset type
  uncovered_techniques = relevant_techniques - covered_techniques
  
  risk_score = asset_criticality * uncovered_technique_count * avg_technique_severity
```

Example:
- Production RDS database (high criticality)
- Missing coverage for T1530 (Data from Cloud Storage)
- Risk score: HIGH

**2. Detection Quality**
```
For each detection:
  quality_score = (
    confidence_score * 0.4 +
    (1 - false_positive_rate) * 0.3 +
    recency_score * 0.2 +
    triggered_recently_score * 0.1
  )
```

Where:
- `confidence_score`: Mapping confidence
- `false_positive_rate`: If known from SIEM
- `recency_score`: How recently detection was created/updated
- `triggered_recently_score`: Has it actually fired in last N days?

**3. Coverage Robustness**
```
For each technique:
  robustness = min(detection_count, 3) / 3
  
  If all detections use same detection_type:
    → Penalty: Single point of failure in detection method
  
  If all detections monitor same log source:
    → Penalty: Vulnerable to log source failure
```

**Outputs**:
- Risk heatmap: Assets × Techniques → Risk score
- Detection quality report: Which detections are low quality?
- Recommended improvements: "Add redundant detection for T1078 using different method"

---

### D. VALIDATION ACTIONS

#### Action: ValidateDetection
```
ValidateDetection(detection_id, validation_level)
```

**Purpose**: Verify that a detection is still functional and effective

**Preconditions**:
- Detection is enabled (`detection_status[detection_id] == enabled`)
- Test data or validation method available
- Sufficient permissions to read detection config

**Parameters**:
- `validation_level`: Enum {syntax, semantic, functional}
  - `syntax`: Detection config is parseable
  - `semantic`: References valid resources (log groups, metrics exist)
  - `functional`: Detection actually works (test trigger if safe)

**Effects**:
- `detection_health[detection_id]` updated
- `validation_timestamp[detection_id]` set to now
- If broken: `detection_health.status = broken` and alert generated
- If drifted: `api_drift_detected[detection_id] = true`

**Validation Methods**:

**1. Syntax Validation**
```
Try to parse detection config:
  - CloudWatch Logs Insights query: Valid syntax?
  - EventBridge pattern: Valid JSON?
  - Lambda code: Compiles/loads without errors?

Result: healthy | broken
```

**2. Semantic Validation**
```
Check that referenced resources exist:
  - Log groups: Does the log group exist?
  - Metrics: Is the metric namespace valid?
  - SNS topics: Does the alert destination exist?
  - IAM roles: Does Lambda have required permissions?

Result: healthy | degraded | broken
```

**3. Functional Validation (Risky)**
```
CAUTION: May trigger actual alerts

Option A: Dry-run (if supported by service)
  - Test query against sample data
  - Verify expected results

Option B: Review historical triggers
  - Has detection fired in last 30 days?
  - If never triggered: Could be dead or environment doesn't have activity

Option C: Controlled test (staging only)
  - Generate known-malicious activity
  - Verify detection fires
```

**API Drift Detection**:
```
Compare detection config against known API deprecations:
  For each APIDeprecation:
    If detection references deprecated API:
      → api_drift_detected[detection_id] = true
      → detection_health.status = degraded
      → Include migration guidance in report
```

**Common Failure Modes**:
- References deleted log group
- Lambda function no longer exists
- SNS topic deleted (silent failure)
- API field renamed/deprecated
- Permissions revoked
- Query syntax incompatible with new API version

---

#### Action: MonitorAPIDeprecations
```
MonitorAPIDeprecations(provider, lookback_period)
```

**Purpose**: Track cloud provider API changes that could break detections

**Preconditions**:
- Access to provider's deprecation announcements (RSS, API, docs)
- List of APIs currently used by detections

**Parameters**:
- `lookback_period`: How far back to scan for announcements (e.g., "6 months")

**Effects**:
- `APIDeprecation` entities created for discovered deprecations
- Detections using deprecated APIs flagged
- `detection_health` updated for affected detections
- Proactive alerts sent before end-of-life date

**Data Sources**:

**AWS**:
- AWS What's New RSS feed
- AWS SDK release notes
- Service-specific documentation changes
- Personal Health Dashboard (account-specific)

**GCP**:
- Google Cloud Release Notes
- API version deprecation notices
- Cloud SDK changelogs

**Challenges**:
- No standardized deprecation announcement format
- Announcements may be in human-readable text (requires parsing)
- Lead time varies (6 months to 2 years)
- Not all breaking changes are announced

**Matching Logic**:
```
For each deprecation announcement:
  Extract: API name, service, deprecation_date, replacement
  
  For each detection:
    If detection.raw_config contains deprecated API name:
      Create APIDeprecation entity
      Link to affected detections
      Calculate urgency (time until EOL)
```

**Proactive Actions**:
- 6 months before EOL: Info alert
- 3 months before EOL: Warning alert
- 1 month before EOL: Critical alert
- Post-EOL: Detection marked as broken

---

### E. REMEDIATION ACTIONS

#### Action: RecommendDetection
```
RecommendDetection(gap: CoverageGap, recommendation_strategy)
```

**Purpose**: Suggest specific detection(s) to close a coverage gap

**Preconditions**:
- Gap has been identified
- Detection template library available
- Account's enabled services known

**Parameters**:
- `recommendation_strategy`: Enum {simple, redundant, multi_method}
  - `simple`: One detection to cover the technique
  - `redundant`: Multiple detections for robustness
  - `multi_method`: Detections using different approaches

**Effects**:
- Recommended detection(s) added to `CoverageGap.recommended_detections`
- (Optional) IaC template generated for deployment

**Recommendation Logic**:

**1. Template Matching**
```
For each technique in gap:
  Query template library for technique_id
  Filter templates by:
    - Compatible with account's cloud provider
    - Uses services enabled in account
    - Matches account's detection patterns (naming, tagging)
  
  Rank templates by:
    - Confidence (how well it covers technique)
    - Simplicity (fewer dependencies = better)
    - Cost (CloudWatch vs GuardDuty pricing)
```

**2. Custom Generation**
```
If no template exists:
  Analyze technique's detection guidance from MITRE
  Identify required data sources (CloudTrail, VPC Flow, etc.)
  Generate detection logic:
    - Which log group to query?
    - What event names to match?
    - What conditions to check?
  
  Output: Detection config skeleton requiring manual refinement
```

**3. Context-Aware Recommendations**
```
Consider account context:
  - If account has GuardDuty enabled → Prefer GuardDuty-based detection
  - If account uses Splunk/SIEM → Recommend log forwarding + SIEM rule
  - If account has mature IaC → Provide Terraform/CDK
  - If account is small → Prefer simple CloudWatch alarms
```

**Example Recommendations**:

**Gap: T1078.004 (Valid Accounts: Cloud Accounts)**
```
Recommendation 1: CloudWatch Logs Insights query
  - Query: Filter CloudTrail for failed AssumeRole attempts
  - Frequency: Every 5 minutes
  - Alert: SNS topic → email/Slack
  - Cost: ~$5/month
  - Confidence: 0.9

Recommendation 2: EventBridge rule
  - Pattern: Match AssumeRole with errorCode field
  - Action: Lambda to enrich + alert
  - Cost: ~$2/month
  - Confidence: 0.95
  
Recommendation 3: GuardDuty finding
  - Managed detection: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
  - Cost: GuardDuty pricing (already enabled)
  - Confidence: 0.85 (broader than just AssumeRole)
```

**Quality Checks**:
- Does recommended detection actually cover the technique?
- Is it feasible in this account (services available)?
- Does it duplicate existing detections?
- What is the expected false positive rate?

---

#### Action: GenerateIaC
```
GenerateIaC(recommended_detection, target_account, iac_format)
```

**Purpose**: Create deployable infrastructure-as-code for a recommended detection

**Preconditions**:
- Detection recommendation exists
- IaC format specified (Terraform, CDK, CloudFormation, Pulumi)
- Target account's infrastructure patterns known (optional, for consistency)

**Parameters**:
- `iac_format`: Enum {terraform, cdk, cloudformation, pulumi}

**Effects**:
- Deployable IaC file created
- Dependencies identified (SNS topics, IAM roles, log groups)
- Documentation included (what it detects, how to customize)

**Generation Strategy**:

**1. Template-Based**
```
Use pre-written IaC templates:
  detection_templates/
    cloudwatch_failed_login.tf
    eventbridge_new_instance.tf
    guardduty_config.tf

Parameterize:
  - Account ID
  - Region
  - SNS topic ARN
  - Log group names
  - Alert email/Slack webhook
```

**2. Dynamic Generation**
```
Build IaC from detection config:
  
  1. Parse detection logic
  2. Identify required resources:
     - CloudWatch Logs Insights → saved query + scheduled query
     - EventBridge → rule + target (SNS/Lambda)
     - CloudWatch Alarm → metric filter + alarm + SNS topic
  3. Generate resource definitions in target format
  4. Add dependencies (SNS topics, IAM policies)
  5. Add variables for customization
```

**Example Output (Terraform)**:
```hcl
# Detection: Failed AssumeRole attempts
# MITRE: T1078.004 (Valid Accounts: Cloud Accounts)

resource "aws_cloudwatch_log_metric_filter" "failed_assume_role" {
  name           = "failed-assume-role-attempts"
  log_group_name = var.cloudtrail_log_group
  
  pattern = <<PATTERN
{ ($.eventName = "AssumeRole") && ($.errorCode = "*") }
PATTERN

  metric_transformation {
    name      = "FailedAssumeRoleAttempts"
    namespace = "Security/IAM"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "failed_assume_role_alarm" {
  alarm_name          = "failed-assume-role-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.failed_assume_role.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.failed_assume_role.metric_transformation[0].namespace
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Alerts when 5+ failed AssumeRole attempts detected in 5 minutes"
  alarm_actions       = [var.sns_topic_arn]
}

# Variables
variable "cloudtrail_log_group" {
  description = "CloudWatch Log Group where CloudTrail logs are stored"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic for security alerts"
  type        = string
}
```

**Considerations**:

**Infrastructure Dependencies**:
- SNS topics for alerting (create if doesn't exist?)
- IAM roles for Lambda execution
- Log groups (assume exists or create?)
- KMS keys for encryption

**Consistency with Existing Infrastructure**:
- Match account's naming conventions
- Use account's tagging strategy
- Integrate with existing SIEM/alerting
- Respect account's IaC patterns (modules, remote state)

**Documentation**:
- What the detection does
- Why it's recommended
- How to customize thresholds
- Expected false positive rate
- Testing instructions

---

## 4. CONSTRAINTS (Problem Boundaries & Rules)

### A. Access Constraints

#### Permission Boundaries
- **Requirement**: Read-only access to cloud accounts
- **Rationale**: Cannot modify production security controls during scanning
- **Implementation**: IAM policies with explicit deny on write/delete actions
- **AWS Example**:
  ```json
  {
    "Effect": "Allow",
    "Action": [
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "guardduty:Get*",
      "guardduty:List*",
      "events:Describe*",
      "events:List*"
    ],
    "Resource": "*"
  }
  ```
- **Risk**: Even read-only access exposes sensitive security configuration

#### Rate Limits
- **Problem**: Cloud APIs have rate limits (e.g., AWS: 10 requests/second per service)
- **Impact**: Large accounts may take hours to scan completely
- **Mitigation Strategies**:
  - Exponential backoff on 429 errors
  - Parallelize across services (not within service)
  - Cache results aggressively
  - Incremental scanning (only changed resources)
- **Cost**: API calls may incur charges in some services

#### Credential Expiry
- **Problem**: Temporary credentials (STS tokens) expire during long scans
- **Typical Lifetime**: 1 hour (can be extended to 12 hours)
- **Mitigation**:
  - Detect expiry proactively (refresh before expiration)
  - Checkpoint progress (resume from last successful service)
  - Use long-lived credentials for scanning (if policy allows)

#### Multi-Region Complexity
- **Problem**: Detections may be region-specific
- **AWS**: 20+ regions to scan
- **GCP**: 30+ regions/zones
- **Impact**: Scan time multiplies by number of regions
- **Strategy**:
  - Parallel region scanning
  - Filter to active regions only (skip regions with zero resources)
  - Global resources (IAM) scanned once

#### Multi-Account Scale
- **Problem**: Enterprise environments have 10s to 100s of accounts
- **Organization Structure**: AWS Organizations, GCP Folders
- **Cross-Account Access**:
  - AWS: AssumeRole to each account from central account
  - GCP: Service account with organization-level viewer role
- **Challenges**:
  - Managing credentials for all accounts
  - Accounts may have different IAM policies
  - Some accounts may be inaccessible (permission denied)

---

### B. Mapping Constraints

#### Ambiguity
- **Problem**: Single detection may map to multiple techniques
- **Example**:
  ```
  Detection: "Alert on failed SSH login attempts"
  Could be:
    - T1110.001 (Brute Force: Password Guessing)
    - T1078.003 (Valid Accounts: Local Accounts)
    - T1021.004 (Remote Services: SSH)
  
  Which is correct? All of them, depending on context.
  ```
- **Resolution Strategies**:
  - Multi-mapping: Allow one detection → many techniques
  - Confidence scores: Rank mappings by likelihood
  - Context-aware: Use additional signals (asset type, alert history)
  - User feedback: Allow manual correction of mappings

#### Incompleteness
- **Problem**: Detection logic may be too complex to fully parse
- **Examples**:
  - Custom Lambda code with complex business logic
  - Queries with 20+ conditions and nested logic
  - Machine learning-based detections (black box)
  - External integrations (SIEM rules not visible)
- **Impact**: Cannot confidently map to MITRE techniques
- **Mitigation**:
  - Partial mapping: Map what can be understood
  - Confidence score: Reflect uncertainty (e.g., 0.4)
  - Manual review: Flag for human analyst
  - User annotation: Allow users to manually map

#### Confidence Variability
- **Problem**: Different mapping methods have different accuracy
- **Spectrum**:
  - **Manual mapping by expert**: 95-100% confidence
  - **Pattern matching on known indicators**: 80-90% confidence
  - **NLP semantic similarity**: 60-80% confidence
  - **ML inference (untrained)**: 40-60% confidence
- **Requirement**: Transparency in confidence scoring
- **Use Cases**:
  - High-confidence only: Executive reporting (no false claims)
  - All mappings: Comprehensive analysis (accept some errors)
  - Medium+ confidence: Gap analysis (balance coverage vs accuracy)

#### M:N Relationship Complexity
- **Reality**: Many-to-many between detections and techniques
  ```
  One detection → many techniques:
    "Monitor EC2 launch + unusual region" → T1578.002 + T1535
  
  One technique → many detections:
    T1078 (Valid Accounts) ← Login monitoring, MFA failures, unusual location, unusual time
  ```
- **Implications**:
  - Cannot simply count: 5 detections ≠ 5 techniques covered
  - Overlap is complex: Which detections provide unique coverage?
  - Redundancy is good: Multiple detections for critical techniques desired
- **Data Model**: Graph (not tree) of relationships

#### Platform Specificity
- **Problem**: MITRE techniques have platform tags (IaaS, SaaS, Linux, Windows, etc.)
- **Example**:
  ```
  T1078 (Valid Accounts) applies to:
    - IaaS (AWS, GCP, Azure)
    - SaaS (M365, Salesforce)
    - Linux
    - Windows
  
  A detection for "failed AWS IAM login" only covers the IaaS platform.
  ```
- **Requirement**: Filter MITRE techniques by applicable platforms
- **Challenge**: Platform granularity (AWS EC2 Linux vs AWS Lambda?)
- **Solution**: Tag techniques with specific applicability: `{aws_iam, gcp_iam, azure_ad}`

---

### C. Coverage Constraints

#### Overlap is Good (Sometimes)
- **Principle**: Redundancy for critical techniques is desirable, not a flaw
- **Example**:
  ```
  T1078 (Valid Accounts) covered by:
    1. CloudWatch alarm on failed logins
    2. GuardDuty finding for credential access
    3. Lambda function for anomalous login time
  
  This is GOOD: If one breaks, coverage persists.
  ```
- **But**: 10 detections for same technique = excessive, creates noise
- **Heuristic**:
  - 1 detection = risky (single point of failure)
  - 2-3 detections = ideal (redundancy without clutter)
  - 4+ detections = excessive (consolidate or review)

#### False Coverage
- **Problem**: Detection exists but doesn't actually fire
- **Causes**:
  - Logic error (never matches any events)
  - Data source doesn't exist (log group empty)
  - Thresholds too high (alert never triggered)
  - Disabled but still in config
- **Risk**: False sense of security ("we're covered!")
- **Detection**:
  - Check `last_triggered` timestamp
  - If never fired in 90 days → investigate
  - Test with synthetic data (if safe)
- **Reporting**: "Coverage (untested)" vs "Coverage (validated)"

#### Context Dependency
- **Problem**: Coverage relevance depends on deployed assets/services
- **Example**:
  ```
  Account has:
    - 100 EC2 instances
    - 0 RDS databases
    - 0 S3 buckets
  
  Question: Should we report gaps for S3-specific techniques?
  
  Answer: Depends on use case:
    - Compliance: Yes, must cover all applicable techniques
    - Risk-based: No, no risk if no S3 exists
    - Proactive: Yes, might deploy S3 in future
  ```
- **Solution**:
  - Asset-aware gap analysis (filter by deployed resources)
  - Full gap analysis (show all gaps, flag irrelevant ones)
  - Let user choose perspective

#### Detection Quality vs Quantity
- **False Equivalence**: 100% coverage ≠ good security
- **Quality Factors**:
  - False positive rate (high FP = alert fatigue = ignored)
  - Detection latency (detects 2 weeks later = too late)
  - Coverage depth (detects technique but not all variants)
- **Example**:
  ```
  Scenario A: 90% coverage, low false positives, 5 min latency
  Scenario B: 100% coverage, high false positives, 1 hour latency
  
  Scenario A is better despite lower coverage %.
  ```
- **Metric**: Quality-adjusted coverage score

#### Temporal Nature
- **Reality**: Coverage degrades over time without intervention
- **Causes**:
  - Detections disabled (alert fatigue → turned off)
  - Detections deleted (cleanup, migrations)
  - Detections broken (API deprecation, config drift)
  - New assets deployed (coverage gap emerges)
  - MITRE updated (new techniques not covered)
- **Requirement**: Continuous monitoring, not point-in-time
- **Alert Strategy**:
  - Coverage drops by >10% → high-priority alert
  - Coverage drops to zero for critical technique → critical alert

---

### D. Temporal Constraints

#### Staleness
- **Problem**: Detection configs change frequently (weekly? daily?)
- **Implication**: Static snapshot becomes stale quickly
- **Solution**:
  - Periodic re-scanning (daily/weekly)
  - Change detection (scan only if config changed)
  - Near-real-time (event-driven scanning via CloudTrail/Cloud Logging)
- **Trade-off**: Frequency vs cost/performance

#### Drift Detection Window
- **Requirement**: Minimum 2 snapshots to detect drift
- **Practical Window**: 30-90 days of history
- **Too Short**: Cannot distinguish drift from normal changes
- **Too Long**: Historical data storage costs
- **Optimal**: 90 days (captures quarterly changes)

#### MITRE Evolution
- **Reality**: MITRE ATT&CK updated ~2x per year
- **Changes**:
  - New techniques added
  - Existing techniques revised
  - Deprecated techniques removed
  - Sub-techniques reorganized
- **Impact**: Mappings become outdated
- **Migration Strategy**:
  - Version all mappings (mapped against v13.1)
  - Automated remapping when MITRE updates
  - Notify user of new gaps from new techniques
  - Preserve historical mappings (for trend analysis)

#### API Deprecation Lead Time
- **Typical Timeline**:
  - Announcement → 6-12 months → deprecation → 6 months → EOL
- **Example (AWS)**:
  - 2024-01: Announce CloudWatch API field deprecation
  - 2024-07: Mark as deprecated (still works)
  - 2025-01: Remove field (breaking change)
- **Requirement**: Track from announcement, not just deprecation
- **Action Timeline**:
  - Announcement: Info notification
  - 6 months before EOL: Warning
  - 3 months: Urgent
  - 1 month: Critical
  - Post-EOL: Mark detections as broken

#### Validation Frequency
- **Problem**: Cannot validate all detections continuously
- **Cost**:
  - API calls (rate limits)
  - Compute (parsing/testing)
  - Potential alert noise (test triggers)
- **Strategy**:
  - Prioritize: Validate critical detections daily, others weekly
  - Triggered-based: Validate after config changes
  - Sampling: Validate random subset daily (full coverage over time)
- **SLA**: All detections validated at least once per 30 days

---

### E. Accuracy Constraints

#### False Positives (Mapping Errors)
- **Definition**: Detection mapped to technique incorrectly
- **Example**:
  ```
  Detection: "EC2 instance stopped"
  Incorrectly mapped to: T1496 (Resource Hijacking)
  Actually: Legitimate operational activity
  ```
- **Causes**:
  - Ambiguous detection descriptions
  - Overly aggressive pattern matching
  - ML model errors
  - Misunderstanding of technique scope
- **Impact**: Over-estimated coverage (worse than gaps!)
- **Mitigation**:
  - Conservative confidence thresholds
  - Human review of low-confidence mappings
  - Feedback loop (user corrections improve future mappings)

#### False Negatives (Missed Mappings)
- **Definition**: Detection covers technique but not mapped
- **Causes**:
  - Complex custom logic not parsed
  - Novel detection approach not in pattern library
  - Vendor-managed detections (black box)
- **Impact**: Under-estimated coverage (false gaps)
- **Detection**: User feedback ("this detection covers T1078!")
- **Mitigation**:
  - Manual mapping interface
  - Periodic re-analysis with improved parsers
  - Community-contributed mappings

#### Custom Logic Opacity
- **Problem**: Lambda/Cloud Function code is black box
- **Example**:
  ```python
  # What does this Lambda do? Impossible to know without analysis.
  def lambda_handler(event, context):
      # ... 500 lines of code ...
      # Maybe detects something? Maybe not?
  ```
- **Approaches**:
  - **Static Analysis**: Parse code for security-relevant patterns
  - **User Annotation**: Ask user to describe what it detects
  - **Heuristics**: Check function name, triggers, IAM permissions
  - **Fallback**: Mark as "custom detection, unmapped"
- **Limitation**: Cannot guarantee completeness

#### Implicit Coverage
- **Problem**: Managed services detect threats without exposing details
- **Example**:
  - GuardDuty: Detects 100+ finding types, maps to MITRE
  - But: Cannot see individual "rules" or customize
- **Approach**:
  - Treat as single high-level detection
  - Map to all techniques GuardDuty claims to detect (per AWS docs)
  - Note: Less granular than custom detections
- **Transparency**: Document that coverage is vendor-claimed, not verified

#### Vendor Gaps
- **Reality**: Cloud providers' own detection services have coverage gaps
- **Example**:
  - GuardDuty covers ~30% of MITRE ATT&CK (estimate)
  - Security Command Center similar
- **User Expectation**: "I have GuardDuty, I'm covered!"
- **Truth**: Still many gaps requiring custom detections
- **Communication**: Be transparent about managed service limitations

---

### F. Computational Constraints

#### Parsing Complexity
- **Problem**: Some detection queries are computationally expensive to analyze
- **Examples**:
  - CloudWatch Logs Insights with 50+ fields, 20+ conditions
  - Nested subqueries
  - Regular expressions
  - Complex time-window logic
- **Impact**: Parsing may take seconds per detection (× 1000 detections = slow)
- **Mitigation**:
  - Timeout per detection (e.g., 5 seconds)
  - Progressive parsing (shallow → deep on demand)
  - Cache parsing results (only re-parse on change)
  - Parallel processing (parse 10 detections simultaneously)

#### NLP Accuracy
- **Problem**: Intent extraction from natural language is imperfect
- **Sources of Error**:
  - Ambiguous descriptions ("monitors unusual activity")
  - Missing descriptions (detection named "rule-42")
  - Domain-specific jargon (may not be in NLP model)
- **Accuracy**: Best-case 70-80% for NLP-based mapping
- **Mitigation**:
  - Use multiple signals (name + description + config)
  - Lower confidence scores for NLP mappings
  - Human review loop for uncertain mappings

#### Real-Time Requirements
- **User Expectation**: Near-instant coverage reports
- **Reality**: Large accounts may require:
  - 5-10 minutes to scan (1000s of API calls)
  - 5-10 minutes to parse (complex detection logic)
  - 1-2 minutes to map (NLP/ML inference)
  - Total: 15-30 minutes for first-time scan
- **UX Strategy**:
  - Progressive loading (show results as available)
  - Async processing (scan in background, notify when ready)
  - Incremental updates (fast re-scan after first scan)
  - Pre-computed reports (scheduled nightly, instant retrieval)

#### Storage
- **Historical Data Growth**: Linear with time
- **Example**:
  ```
  Snapshot per day × 365 days × 100 accounts:
    - Detection configs: ~1MB per account per day
    - Total: 100 accounts × 1MB × 365 = 36.5 GB/year
  ```
- **Cost**: S3 storage is cheap (~$0.023/GB/month)
- **Strategy**:
  - Compress snapshots (JSON → gzip)
  - Downsample (keep daily for 30 days, weekly for 1 year, monthly after)
  - Summarize (store diffs, not full snapshots)

#### Cross-Cloud Normalization
- **Problem**: Semantic equivalence is heuristic, not perfect
- **Example**:
  ```
  AWS: iam:AssumeRole (cross-account access)
  GCP: iam.serviceAccounts.actAs (service account impersonation)
  
  Similar, but not identical. How to normalize?
  ```
- **Approach**:
  - Maintain equivalence tables (manually curated)
  - Accept imperfect normalization (flag confidence)
  - Preserve cloud-specific details (for reference)
- **Limitation**: Some features have no equivalent (asymmetric)

---

### G. Business/Product Constraints

#### User Expertise Variability
- **Spectrum**:
  - **Novice**: "What's MITRE ATT&CK?"
  - **Intermediate**: Knows MITRE, not detection engineering
  - **Expert**: Security architect, deep MITRE knowledge
- **Design Implication**: Multi-level UX
  - Novice: Simple red/yellow/green coverage score
  - Intermediate: Per-tactic breakdown, gap list
  - Expert: Detailed technique mappings, confidence scores, raw data export
- **Documentation**: Tiered explanations (basic → advanced)

#### Actionability
- **Problem**: Identifying gaps without remediation is useless
- **User Frustration**: "You told me I have 50 gaps. Now what?"
- **Requirement**: Every gap must have actionable recommendation
  - Recommended detection(s)
  - IaC template for deployment
  - Estimated effort/cost
  - Priority/risk score
- **Value Proposition**: Not just analysis, but solution

#### Cost Sensitivity
- **Reality**: Continuous scanning incurs cloud API costs
- **AWS Example**:
  - CloudTrail API: $0.005 per 1000 API calls
  - 1000 API calls per scan × 365 scans/year = ~$2/year (negligible)
- **But**: At scale (1000 accounts) = $2000/year
- **Consideration**:
  - Document costs transparently
  - Offer cost optimization (incremental scans, sampling)
  - Bill per account (predictable pricing)

#### Alert Fatigue
- **Problem**: Too many gap notifications → ignored
- **Causes**:
  - Low-priority gaps treated same as critical
  - Repeated alerts for same gaps
  - Noise from low-confidence mappings
- **Mitigation**:
  - Risk-based prioritization (critical gaps first)
  - Suppress acknowledged gaps (user accepted risk)
  - Digest emails (daily summary, not per-gap alert)
  - Configurable alert thresholds

#### Vendor Lock-in Avoidance
- **Principle**: Do not require agent deployment or SDK integration
- **Rationale**:
  - Users want lightweight, non-invasive tools
  - Agents = performance impact, operational burden
  - SDK = code changes, vendor dependency
- **Approach**: API-only, read-only access
- **Benefit**: Easy adoption, easy removal

---

## 5. OPEN QUESTIONS / UNRESOLVED AMBIGUITIES

These are critical design decisions that require further exploration:

### 1. Multi-Technique Detection Handling
**Question**: How should we handle detections that span multiple techniques?

**Example**:
```
Single query detects:
  - Privilege escalation (T1548)
  - Lateral movement (T1021)
  - Credential dumping (T1003)

Should this count as:
  Option A: Full coverage for all 3 techniques (optimistic)
  Option B: Partial coverage for all 3 (conservative)
  Option C: Full for primary, partial for secondary (nuanced)
```

**Trade-offs**:
- Option A: Over-estimates coverage
- Option B: Under-estimates coverage
- Option C: Requires defining "primary" (subjective)

**Recommendation Needed**: Define mapping cardinality policy

---

### 2. Coverage Weighting by Severity/Prevalence
**Question**: Should all techniques be weighted equally in coverage scoring?

**Arguments For Weighting**:
- Not all gaps are equal
- T1190 (Exploit Public-Facing Application) is more critical than T1036 (Masquerading)
- Techniques frequently exploited (per CISA KEV, MITRE stats) should be prioritized

**Arguments Against Weighting**:
- Introduces subjectivity (who defines weights?)
- May lead to false sense of security (80% coverage, but gaps in critical techniques)
- Complexity in scoring algorithm

**Options**:
- **Equal weights**: Simple, objective, but naive
- **MITRE-based weights**: Use technique prevalence from MITRE (if available)
- **User-defined weights**: Let users prioritize based on their threat model
- **Hybrid**: Default weights with user override

**Recommendation Needed**: Define weighting strategy

---

### 3. Implicit Coverage from Managed Services
**Question**: How to handle black-box managed detections (GuardDuty, SCC)?

**Problem**:
```
GuardDuty FindingType: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
MITRE Mapping: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

But: GuardDuty doesn't expose the detection logic.
Cannot verify coverage quality, cannot see false positive rate, cannot customize.
```

**Options**:
- **Trust vendor claims**: Map based on AWS/GCP documentation
  - Pro: Easy
  - Con: Cannot verify, may be inaccurate
- **Treat as black box**: Single detection mapped to "managed service coverage"
  - Pro: Honest about uncertainty
  - Con: Less granular reporting
- **Test empirically**: Generate test attacks, verify GuardDuty detects
  - Pro: Validated coverage
  - Con: Requires test environment, ethical concerns

**Recommendation Needed**: Define approach for managed services

---

### 4. Confidence Threshold for "Covered"
**Question**: What confidence level constitutes actionable coverage?

**Spectrum**:
```
Confidence 1.0 (100%): Manual expert validation
Confidence 0.9: High-confidence pattern match
Confidence 0.7: NLP-based inference
Confidence 0.5: ML prediction
Confidence 0.3: Speculative mapping
```

**Question**: At what threshold do we claim "technique is covered"?

**Options**:
- **Conservative (>= 0.8)**: High confidence only
  - Pro: No false claims
  - Con: May under-report coverage
- **Moderate (>= 0.6)**: Include likely mappings
  - Pro: Balance accuracy and coverage
  - Con: Some errors expected
- **Aggressive (>= 0.4)**: Include uncertain mappings
  - Pro: Maximum coverage visibility
  - Con: High false positive rate

**User-Facing Question**: Should we let users choose threshold?

**Recommendation Needed**: Define default threshold and user configurability

---

### 5. Detection Validation Without Triggering Alerts
**Question**: How to validate detections are functional without causing alert noise?

**Challenges**:
```
Option 1: Dry-run (syntax check only)
  - Pro: Safe, no alerts
  - Con: Doesn't verify detection actually works

Option 2: Test trigger (controlled attack simulation)
  - Pro: Validates end-to-end
  - Con: May trigger real alerts, confuse security team

Option 3: Historical analysis (check if detection has fired recently)
  - Pro: Non-invasive
  - Con: Silent failure may go undetected (false negatives)

Option 4: Shadow mode (run query, don't alert)
  - Pro: Safe validation
  - Con: Requires system modification (not always possible)
```

**Question**: What is acceptable validation approach per detection type?

**Recommendation Needed**: Define validation strategy per service (CloudWatch vs GuardDuty vs Lambda)

---

### 6. Custom Detection Logic (Lambda/Cloud Functions)
**Question**: How deeply should we analyze custom code?

**Spectrum**:
```
Level 0: Ignore (treat as black box)
  - Effort: 0
  - Accuracy: 0%

Level 1: Metadata only (function name, triggers, IAM permissions)
  - Effort: Low
  - Accuracy: ~30% (heuristics)

Level 2: Static analysis (AST parsing, pattern matching)
  - Effort: Medium
  - Accuracy: ~60%

Level 3: Dynamic analysis (execute in sandbox)
  - Effort: High
  - Accuracy: ~80%
  - Risk: Code execution concerns

Level 4: Manual review (security engineer reads code)
  - Effort: Very high
  - Accuracy: 95%+
  - Scalability: Poor (doesn't scale)
```

**Question**: What level is feasible for MVP? For production?

**Recommendation Needed**: Define approach and resource allocation

---

### 7. Temporal Decay of Mappings
**Question**: Should old, unvalidated mappings degrade in confidence over time?

**Rationale**:
```
Mapping created: 2024-01-01, confidence 0.9
Detection last modified: 2024-01-01
Current date: 2024-12-18

Detection hasn't been validated in 11 months.
Cloud APIs may have changed. Detection may be stale.

Should confidence decay to 0.7? 0.5? Stay 0.9?
```

**Arguments For Decay**:
- Reflects uncertainty from staleness
- Encourages re-validation
- More honest about confidence

**Arguments Against Decay**:
- Adds complexity
- May under-report coverage unnecessarily
- Detection may still work fine

**Options**:
- No decay (confidence is static)
- Linear decay (drop 0.05 per month unvalidated)
- Step decay (drop to 0.7 after 6 months, 0.5 after 1 year)
- Event-based (decay only on MITRE version change or API deprecation)

**Recommendation Needed**: Define decay policy

---

### 8. Asset-Specific Coverage Scoping
**Question**: Should coverage gaps be filtered by deployed assets?

**Example**:
```
Account has:
  - EC2 instances: Yes
  - RDS databases: No
  - S3 buckets: No

Technique T1530 (Data from Cloud Storage) requires S3.

Should we report this as a gap?

Option A: Yes, for compliance (must cover all applicable techniques)
Option B: No, for risk (no S3 = no risk)
Option C: Report but mark as "not applicable" (transparency)
```

**Trade-offs**:
- Option A: Compliance-focused, may overwhelm with irrelevant gaps
- Option B: Risk-focused, may miss future deployments
- Option C: Flexible, but requires clear UX

**Question**: Should this be a user preference or default behavior?

**Recommendation Needed**: Define scoping strategy

---

### 9. Detection Quality Metrics Integration
**Question**: How to incorporate false positive rate and other quality metrics?

**Ideal World**:
```
Coverage = (# detections × quality_score) per technique

Where quality_score = (
  mapping_confidence × 0.4 +
  (1 - false_positive_rate) × 0.3 +
  detection_latency_score × 0.2 +
  last_triggered_recency_score × 0.1
)
```

**Reality**:
- False positive rate: Usually unknown (requires SIEM integration)
- Detection latency: Varies by service (CloudWatch = minutes, GuardDuty = near-real-time)
- Last triggered: May not be accessible via API

**Question**: Proceed without quality metrics (simple count) or wait for integration?

**Recommendation Needed**: Define MVP scope vs future enhancement

---

### 10. Multi-Cloud Normalization Equivalence
**Question**: How to handle asymmetric features between AWS and GCP?

**Example**:
```
AWS GuardDuty has:
  - 50+ finding types
  - Deep integration with AWS services
  - Managed threat intelligence

GCP Security Command Center has:
  - 30+ finding types
  - Different focus areas
  - Different coverage

How to represent this in unified coverage view?

Option A: Show per-cloud coverage (AWS: 80%, GCP: 60%)
Option B: Show combined coverage (overall: 70% average?)
Option C: Show union coverage (technique covered if ANY cloud has it)
Option D: Show intersection coverage (technique covered if ALL clouds have it)
```

**Question**: What is most useful for multi-cloud users?

**Recommendation Needed**: Define multi-cloud aggregation strategy

---

## NEXT STEPS

1. **Prioritize Open Questions**: Which need answering before architecture design?
2. **Define Scope**: Which entities/actions are MVP vs future enhancements?
3. **Design Data Model**: Translate entities into database schema
4. **Design API**: Define RESTful endpoints for actions
5. **Architecture**: Choose implementation technologies (language, database, hosting)
6. **Prototype**: Build proof-of-concept for core workflow (scan → parse → map → analyze)

---

## APPENDIX: MITRE ATT&CK Coverage Example

### Example Account Coverage Analysis

**Account**: prod-aws-us-east-1
**Scan Date**: 2024-12-18
**Total Detections**: 47
**Mapped Detections**: 42 (89%)
**Unmapped Detections**: 5 (11%)

#### Coverage by Tactic
```
Initial Access        : 60% (3/5 techniques)
Execution             : 40% (2/5 techniques)
Persistence           : 75% (6/8 techniques)
Privilege Escalation  : 50% (3/6 techniques)
Defense Evasion       : 30% (3/10 techniques) ← CRITICAL GAP
Credential Access     : 66% (4/6 techniques)
Discovery             : 20% (2/10 techniques) ← GAP
Lateral Movement      : 80% (4/5 techniques)
Collection            : 50% (2/4 techniques)
Exfiltration          : 100% (3/3 techniques) ← GOOD
Command and Control   : 60% (3/5 techniques)
Impact                : 33% (2/6 techniques) ← GAP
```

#### Top 5 Critical Gaps
1. **T1562 (Impair Defenses)** - No coverage - CRITICAL
2. **T1070 (Indicator Removal)** - No coverage - HIGH
3. **T1083 (File and Directory Discovery)** - No coverage - MEDIUM
4. **T1018 (Remote System Discovery)** - No coverage - MEDIUM
5. **T1485 (Data Destruction)** - No coverage - CRITICAL

#### Recommended Actions
1. Deploy CloudWatch alarm for GuardDuty detector disablement (covers T1562)
2. Enable CloudTrail S3 object logging with integrity validation (covers T1070)
3. Monitor unusual EC2 Describe* API calls (covers T1083, T1018)
4. Add EventBridge rule for S3 DeleteBucket/DeleteObject (covers T1485)

---

**END OF FORMAL PROBLEM MODEL**
