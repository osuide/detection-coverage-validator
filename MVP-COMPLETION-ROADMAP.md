# Detection Coverage Validator - MVP Completion Roadmap

## Executive Summary

This document provides a comprehensive implementation plan for completing the Detection Coverage Validator MVP. Based on codebase analysis, the system is approximately **92% complete** with all critical and moderate features now implemented. The remaining work focuses on UI integration, testing, and polish.

**Status Update (2025-12-18)**: All 5 phases have been implemented. System now supports AWS + GCP multi-cloud detection scanning, NLP-based mapping, detection health monitoring, Lambda scanner enhancement, gap remediation tracking, MITRE version migration, and enhanced code analysis as an opt-in premium feature.

**Remaining: UI integration and end-to-end testing**

---

## 1. Gap Prioritization and Ranking

### Prioritization Matrix

| Rank | Gap | Business Value | Technical Dependencies | Complexity | MVP Necessity |
|------|-----|---------------|----------------------|------------|---------------|
| 1 | GCP Support | HIGH | None (parallel to AWS) | MEDIUM | MUST-HAVE |
| 2 | NLP-based Mapping | HIGH | Pattern mapper exists | HIGH | SHOULD-HAVE |
| 3 | Detection Health Monitoring | MEDIUM-HIGH | Scan infrastructure exists | MEDIUM | SHOULD-HAVE |
| 4 | Custom Function Parsing | MEDIUM | Scanner base exists | HIGH | COULD-HAVE |
| 5 | Detection Remediation Tracking | MEDIUM | Coverage/gaps exist | LOW | SHOULD-HAVE |
| 6 | MITRE Version Migration | LOW-MEDIUM | MITRE models exist | MEDIUM | COULD-HAVE |
| 7 | Real-time Health Monitoring | LOW | Scheduler exists | HIGH | WON'T-HAVE |
| 8 | Advanced Trend Analytics | LOW | Coverage snapshots exist | MEDIUM | WON'T-HAVE |

### Ranking Rationale

**1. GCP Support (CRITICAL - Rank 1)**
- **Business Value**: Multi-cloud is a key differentiator; GCP adoption is significant in target market
- **Dependencies**: None - can be built in parallel with existing AWS implementation
- **Risk**: Without GCP, product is AWS-only, limiting addressable market by ~30-40%

**2. NLP-based Mapping (CRITICAL - Rank 2)**
- **Business Value**: Current pattern matching covers ~40-50% of detections; NLP could reach 70-80%
- **Dependencies**: Pattern mapper exists as fallback
- **Risk**: Low-quality mappings undermine trust in coverage analysis

**3. Detection Health Monitoring (CRITICAL - Rank 3)**
- **Business Value**: Addresses "false coverage" problem - detections that exist but don't work
- **Dependencies**: Detection model already has `health_score` and `last_triggered_at` fields
- **Risk**: Without this, users may trust broken detections

**4. Custom Function Parsing (CRITICAL - Rank 4)**
- **Business Value**: Lambda/Cloud Functions often contain critical custom detection logic
- **Dependencies**: Scanner base class exists
- **Risk**: Missing coverage for potentially most sophisticated detections

**5. Detection Remediation Tracking (MODERATE - Rank 5)**
- **Business Value**: Closes the loop from gap identification to resolution
- **Dependencies**: Gap analyzer exists
- **Risk**: Users identify gaps but can't track progress

**6. MITRE Version Migration (MODERATE - Rank 6)**
- **Business Value**: MITRE updates 2x/year; mappings become stale
- **Dependencies**: MITRE models exist with version field
- **Risk**: Outdated mappings over time

**7-8. Real-time Health & Advanced Analytics (MODERATE - Rank 7-8)**
- Deferred to post-MVP; scheduler exists for near-real-time capability

---

## 2. MVP Scope Definition

### IN SCOPE (MVP)

| Feature | MVP Scope | Out of Scope (Post-MVP) |
|---------|-----------|------------------------|
| **GCP Support** | Cloud Logging, Security Command Center, Eventarc scanners | Cloud Functions code analysis, Cloud Asset Inventory |
| **NLP-based Mapping** | Sentence transformer-based semantic similarity using detection descriptions | Full ML classifier, feedback loop training |
| **Detection Health** | Staleness detection, syntax validation, reference checks | Functional validation (test triggers), real-time monitoring |
| **Custom Functions** | Lambda/Cloud Function metadata extraction, trigger analysis | Deep static code analysis, dynamic analysis |
| **Remediation Tracking** | Gap status workflow (open -> acknowledged -> remediated) | IaC template generation, automated deployment |
| **MITRE Migration** | Manual migration script, mapping diff report | Automated migration, version comparison UI |

### OUT OF SCOPE (Post-MVP)

- Azure support
- Real-time event-driven scanning
- Advanced trend analytics with ML predictions
- Full Lambda/Cloud Function code analysis
- Automated detection deployment
- SIEM integration for false positive rates

---

## 3. Implementation Phases

### Phase 1: GCP Foundation (Weeks 1-3)

**Objective**: Establish GCP scanning capability at feature parity with core AWS services

**Features Included**:
- GCP Cloud Logging scanner
- GCP Security Command Center scanner
- GCP Eventarc scanner
- GCP indicator library for pattern mapper

**Dependencies**: None

**Deliverables**:
- `/backend/app/scanners/gcp/` directory with 3 scanners
- `/backend/app/mappers/gcp_indicator_library.py`
- Updated scan service to support GCP cloud accounts
- GCP-specific MITRE technique indicators

**Acceptance Criteria**:
- Can scan GCP project for detections
- Detections mapped to MITRE techniques
- Coverage calculated correctly for GCP accounts
- End-to-end test passing

---

### Phase 2: NLP Mapping Engine (Weeks 3-5)

**Objective**: Implement semantic similarity-based mapping for improved coverage

**Features Included**:
- NLP mapper using sentence transformers
- Hybrid mapping pipeline (pattern + NLP)
- Confidence calibration between methods

**Dependencies**: Phase 1 (to test with both AWS and GCP)

**Deliverables**:
- `/backend/app/mappers/nlp_mapper.py`
- MITRE technique embeddings cache
- Updated pattern mapper to use hybrid approach
- Mapping source differentiation in UI

**Acceptance Criteria**:
- NLP mapper achieves >60% recall on test set
- Confidence scores appropriately lower than pattern matching
- Processing time <5 seconds per detection
- Explainable rationale for NLP mappings

---

### Phase 3: Detection Health Monitoring (Weeks 5-7)

**Objective**: Validate that discovered detections are operational

**Features Included**:
- Detection staleness calculator
- Syntax validation per detection type
- Resource reference validator
- Health dashboard in UI

**Dependencies**: Phase 1 (GCP validation rules)

**Deliverables**:
- `/backend/app/validators/` directory with validators
- Health score calculation service
- Detection health API endpoints
- Health status in detection list UI

**Acceptance Criteria**:
- Staleness detected for detections >30 days without update
- Syntax errors identified in CloudWatch/GCP queries
- Missing resource references flagged
- Health score visible in dashboard

---

### Phase 4: Enhanced Mapping & Remediation (Weeks 7-9)

**Objective**: Custom function metadata extraction and gap remediation workflow

**Features Included**:
- Lambda scanner enhancement (function metadata, triggers)
- Cloud Functions scanner (Phase 1 completion)
- Gap status workflow (open -> acknowledged -> remediated -> risk_accepted)
- Remediation notes tracking

**Dependencies**: Phases 1-3

**Deliverables**:
- Enhanced Lambda scanner with trigger analysis
- GCP Cloud Functions scanner
- Gap status model and API
- Remediation tracking UI

**Acceptance Criteria**:
- Lambda functions with CloudWatch/EventBridge triggers detected
- Gap status can be updated via API
- Remediation notes persisted
- Gap history visible in UI

---

### Phase 5: MVP Polish & Migration (Weeks 9-11)

**Objective**: MITRE version migration tooling and MVP stabilization

**Features Included**:
- MITRE ATT&CK version migration script
- Mapping diff report generation
- End-to-end testing
- Documentation

**Dependencies**: Phases 1-4

**Deliverables**:
- `/backend/app/scripts/migrate_mitre_version.py`
- Migration diff report API
- Comprehensive test suite
- User documentation

**Acceptance Criteria**:
- MITRE version upgrade preserves valid mappings
- New techniques identified as gaps
- Deprecated techniques flagged
- All critical bugs resolved

---

## 4. Detailed Technical Approach for Critical Features

### 4.1 GCP Support

**Problem Statement**: The system currently only supports AWS. GCP customers cannot use the product, limiting market reach.

**Technical Approach**:

```
Architecture:
/backend/app/scanners/gcp/
    __init__.py
    cloud_logging_scanner.py      # Log-based metrics, saved queries
    security_command_center.py    # SCC findings and notifications
    eventarc_scanner.py          # Event triggers
    cloud_monitoring_scanner.py   # Alerting policies (Phase 2)
```

**Key Components**:

1. **GCP Authentication Module**
   - Service account key file support
   - Workload identity federation for GKE deployments
   - Credential rotation handling

2. **Cloud Logging Scanner**
   - Scan log-based metrics (`projects/{project}/metrics`)
   - Scan saved queries
   - Parse GCP logging query syntax
   - Extract filter conditions for mapping

3. **Security Command Center Scanner**
   - List notification configs
   - Map SCC finding types to MITRE techniques
   - Track enabled detectors

4. **Eventarc Scanner**
   - List triggers per project/region
   - Extract event filters
   - Parse matching criteria

**Integration Points**:
- `CloudProvider.GCP` already exists in model
- `CloudAccount` model supports GCP provider
- `scan_service.py` needs GCP session factory
- `pattern_mapper.py` needs GCP indicator library

**GCP Indicator Library Structure**:
```python
@dataclass
class GCPTechniqueIndicator:
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    audit_log_methods: list[str]  # e.g., "iam.serviceAccounts.actAs"
    keywords: list[str]
    gcp_services: list[str]
    log_patterns: list[str]
    base_confidence: float = 0.7
```

**Acceptance Criteria**:
- [ ] GCP project can be connected with service account
- [ ] Cloud Logging metrics discovered and parsed
- [ ] SCC findings mapped to MITRE techniques
- [ ] Eventarc triggers discovered
- [ ] Coverage calculation works for GCP accounts
- [ ] UI displays GCP accounts correctly

**Risks & Mitigations**:
- **Risk**: GCP API differences from AWS
  - **Mitigation**: Abstract common interface in `BaseScanner`
- **Risk**: GCP audit log format complexity
  - **Mitigation**: Start with common methods, expand over time

---

### 4.2 NLP-based Mapping

**Problem Statement**: Pattern matching only covers detections with explicit API calls/keywords. Custom detections with descriptive names/descriptions remain unmapped.

**Technical Approach**:

```
Architecture:
/backend/app/mappers/
    nlp_mapper.py               # Sentence transformer-based mapper
    embeddings_cache.py         # Pre-computed MITRE technique embeddings
    hybrid_mapper.py            # Combines pattern + NLP mapping
```

**Key Components**:

1. **Embeddings Generation**
   - Pre-compute embeddings for all MITRE technique descriptions
   - Store in Redis/database for fast retrieval
   - Include: technique name, description, detection guidance, data sources

2. **NLP Mapper**
   ```python
   class NLPMapper:
       def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
           self.model = SentenceTransformer(model_name)
           self.technique_embeddings = self._load_embeddings()

       def map_detection(self, detection: RawDetection) -> list[MappingResult]:
           # Combine detection name, description, config keywords
           detection_text = self._build_detection_text(detection)
           embedding = self.model.encode(detection_text)

           # Find top-k most similar techniques
           similarities = cosine_similarity(embedding, self.technique_embeddings)
           top_k = np.argsort(similarities)[-5:][::-1]

           # Convert to MappingResult with confidence calibration
           return self._build_results(top_k, similarities)
   ```

3. **Hybrid Mapping Pipeline**
   ```python
   class HybridMapper:
       def map_detection(self, detection: RawDetection) -> list[MappingResult]:
           # 1. Try pattern matching first (higher confidence)
           pattern_results = self.pattern_mapper.map_detection(detection)

           # 2. Run NLP for additional coverage
           nlp_results = self.nlp_mapper.map_detection(detection)

           # 3. Merge results, preferring pattern matches
           return self._merge_results(pattern_results, nlp_results)
   ```

4. **Confidence Calibration**
   - Pattern match: 0.7-0.95 base confidence
   - NLP (high similarity >0.8): 0.6-0.7 confidence
   - NLP (medium similarity 0.6-0.8): 0.4-0.6 confidence
   - Below 0.4: Flag for manual review

**Integration Points**:
- `MappingSource.NLP` already exists in model
- Update `scan_service._map_detections()` to use hybrid mapper
- Store `mapping_source` to distinguish in UI

**Acceptance Criteria**:
- [ ] NLP mapper loads and caches technique embeddings
- [ ] Detection text extracted from name, description, config
- [ ] Top-5 technique matches returned with calibrated confidence
- [ ] Pattern + NLP results merged correctly
- [ ] Mapping source visible in UI
- [ ] Processing time <5 seconds per detection

**Risks & Mitigations**:
- **Risk**: Model too large for serverless deployment
  - **Mitigation**: Use MiniLM-L6 (80MB); consider model quantization
- **Risk**: Low-quality embeddings for cloud security domain
  - **Mitigation**: Fine-tune on MITRE descriptions; use detection description augmentation

---

### 4.3 Detection Health Monitoring

**Problem Statement**: Detections may exist but be non-functional (broken queries, missing resources, never triggered). This creates false confidence in coverage.

**Technical Approach**:

```
Architecture:
/backend/app/validators/
    __init__.py
    base_validator.py           # Abstract validator interface
    syntax_validator.py         # Query syntax validation
    reference_validator.py      # Resource reference checks
    staleness_validator.py      # Time-based staleness
    health_calculator.py        # Aggregate health score
```

**Key Components**:

1. **Staleness Validator**
   ```python
   class StalenessValidator:
       STALENESS_THRESHOLDS = {
           "warning": timedelta(days=30),
           "critical": timedelta(days=90),
       }

       def validate(self, detection: Detection) -> ValidationResult:
           days_since_update = (datetime.utcnow() - detection.updated_at).days
           days_since_triggered = (
               (datetime.utcnow() - detection.last_triggered_at).days
               if detection.last_triggered_at else None
           )

           # Staleness based on config age and trigger history
           issues = []
           if days_since_update > 90:
               issues.append("Detection config not updated in 90+ days")
           if days_since_triggered is None:
               issues.append("Detection has never triggered")
           elif days_since_triggered > 30:
               issues.append(f"Detection hasn't triggered in {days_since_triggered} days")

           return ValidationResult(issues=issues, score=self._calculate_score(issues))
   ```

2. **Syntax Validator**
   ```python
   class SyntaxValidator:
       def validate(self, detection: Detection) -> ValidationResult:
           if detection.detection_type == DetectionType.CLOUDWATCH_LOGS_INSIGHTS:
               return self._validate_cloudwatch_query(detection.query_pattern)
           elif detection.detection_type == DetectionType.EVENTBRIDGE_RULE:
               return self._validate_event_pattern(detection.event_pattern)
           # ... etc
   ```

3. **Reference Validator**
   ```python
   class ReferenceValidator:
       async def validate(self, detection: Detection, session: Any) -> ValidationResult:
           issues = []

           # Check log groups exist
           if detection.log_groups:
               for lg in detection.log_groups:
                   if not await self._log_group_exists(session, lg, detection.region):
                       issues.append(f"Log group '{lg}' does not exist")

           # Check SNS topics for alarms
           # Check Lambda functions for targets
           # ... etc

           return ValidationResult(issues=issues)
   ```

4. **Health Calculator**
   ```python
   class HealthCalculator:
       def calculate(
           self,
           staleness: ValidationResult,
           syntax: ValidationResult,
           references: ValidationResult,
       ) -> float:
           weights = {"staleness": 0.3, "syntax": 0.4, "references": 0.3}

           health_score = (
               staleness.score * weights["staleness"] +
               syntax.score * weights["syntax"] +
               references.score * weights["references"]
           )

           return round(health_score, 2)
   ```

**Database Model Updates**:
The `Detection` model already has `health_score` and `last_triggered_at` fields. Add:
```python
# In Detection model
health_status: Mapped[str]  # "healthy", "degraded", "broken", "unknown"
health_issues: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
last_validated_at: Mapped[Optional[datetime]]
```

**Integration Points**:
- Add validation step to scan service after detection discovery
- Add `/api/detections/{id}/validate` endpoint for on-demand validation
- Add health status filter to detection list API
- Add health dashboard component to UI

**Acceptance Criteria**:
- [ ] Staleness detected for detections >30 days old
- [ ] Syntax errors detected in queries/patterns
- [ ] Missing log groups/resources flagged
- [ ] Health score calculated and persisted
- [ ] Health status filterable in API
- [ ] Health indicators visible in UI

**Risks & Mitigations**:
- **Risk**: Reference validation requires cloud API calls (rate limits)
  - **Mitigation**: Batch validation, cache results, validate async
- **Risk**: False positives on "never triggered" (new or rare detections)
  - **Mitigation**: Differentiate "new" vs "stale" based on age

---

### 4.4 Custom Function Parsing (Lambda/Cloud Functions)

**Problem Statement**: Lambda functions and Cloud Functions often contain sophisticated detection logic that pattern matching cannot extract.

**Technical Approach** (MVP - Metadata Only):

```
Architecture:
/backend/app/scanners/aws/
    lambda_scanner.py           # Enhanced Lambda scanner

/backend/app/scanners/gcp/
    cloud_functions_scanner.py  # GCP Cloud Functions scanner
```

**Key Components**:

1. **Lambda Scanner Enhancement**
   ```python
   class LambdaScanner(BaseScanner):
       @property
       def detection_type(self) -> DetectionType:
           return DetectionType.CUSTOM_LAMBDA

       async def scan_region(self, region: str, options: dict) -> list[RawDetection]:
           client = self.session.client("lambda", region_name=region)
           detections = []

           for function in self._list_functions(client):
               # Get function configuration
               config = self._get_function_config(client, function)

               # Analyze event sources (triggers)
               triggers = self._get_event_source_mappings(client, function)

               # Extract security-relevant metadata
               metadata = self._extract_security_metadata(function, config, triggers)

               if self._is_security_detection(metadata):
                   detections.append(RawDetection(
                       name=function["FunctionName"],
                       detection_type=DetectionType.CUSTOM_LAMBDA,
                       source_arn=function["FunctionArn"],
                       region=region,
                       raw_config={
                           "function_name": function["FunctionName"],
                           "runtime": config.get("Runtime"),
                           "triggers": triggers,
                           "environment": config.get("Environment", {}).get("Variables", {}),
                           "security_indicators": metadata,
                       },
                       description=config.get("Description", ""),
                   ))

           return detections

       def _is_security_detection(self, metadata: dict) -> bool:
           # Heuristics to identify security-related functions
           security_keywords = ["security", "alert", "detect", "monitor", "guard", "audit"]

           # Check function name
           name_lower = metadata.get("function_name", "").lower()
           if any(kw in name_lower for kw in security_keywords):
               return True

           # Check triggers (CloudWatch Events, EventBridge, GuardDuty)
           triggers = metadata.get("triggers", [])
           security_triggers = ["events.amazonaws.com", "guardduty", "config", "securityhub"]
           if any(t in str(triggers).lower() for t in security_triggers):
               return True

           return False
   ```

2. **Security Metadata Extraction**
   ```python
   def _extract_security_metadata(self, function, config, triggers) -> dict:
       metadata = {
           "function_name": function["FunctionName"],
           "triggers": [],
           "monitored_services": set(),
           "security_indicators": [],
       }

       # Analyze triggers
       for trigger in triggers:
           if trigger["EventSourceArn"].startswith("arn:aws:events"):
               metadata["triggers"].append("EventBridge")
           elif trigger["EventSourceArn"].startswith("arn:aws:sqs"):
               metadata["triggers"].append("SQS")
           elif trigger["EventSourceArn"].startswith("arn:aws:kinesis"):
               metadata["triggers"].append("Kinesis")

       # Analyze description
       desc = config.get("Description", "").lower()
       if "cloudtrail" in desc:
           metadata["monitored_services"].add("cloudtrail")
       if "guardduty" in desc:
           metadata["monitored_services"].add("guardduty")

       return metadata
   ```

3. **Lambda-to-MITRE Mapping Strategy**
   - Use function name/description for NLP mapping
   - Use trigger source to infer monitored services
   - Map EventBridge triggers using existing event pattern mapper
   - Confidence capped at 0.6 without code analysis

**Acceptance Criteria**:
- [ ] Lambda functions with security-relevant triggers discovered
- [ ] Security metadata extracted from function config
- [ ] Functions mapped to MITRE techniques via NLP on name/description
- [ ] Trigger patterns used to enhance mapping confidence
- [ ] Cloud Functions scanner (GCP) works similarly

**Risks & Mitigations**:
- **Risk**: Cannot determine detection intent without code analysis
  - **Mitigation**: Conservative confidence scores; flag for manual review
- **Risk**: False positives (non-security functions detected)
  - **Mitigation**: Require security keywords or triggers

---

## 5. Open Questions Resolution

### From Problem Model Section 5:

| Question | Decision | Rationale | Implementation |
|----------|----------|-----------|----------------|
| Q1: Multi-Technique Detection Handling | Option A (Full coverage) with confidence adjustment | Multi-technique detections are valuable | Store multiple `DetectionMapping` records |
| Q2: Coverage Weighting | Equal weights for MVP, user-configurable later | Simplicity for MVP | Use `TechniqueIndicator.priority` for gap ordering |
| Q3: Managed Services Coverage | Trust vendor claims with "vendor" source tag | GuardDuty/SCC mappings well-documented | `MappingSource.VENDOR` |
| Q4: Confidence Threshold | >= 0.6 = covered, 0.4-0.6 = partial, < 0.4 = uncovered | Already implemented | Configurable via settings |
| Q5: Detection Validation | Syntax check + reference validation (no test triggers) | Test triggers too risky | Validators are read-only |
| Q6: Custom Detection Depth | Level 1 (metadata only) for MVP | Code analysis complex | Metadata extraction only |
| Q7: Temporal Decay | Event-based (MITRE version change or API deprecation) | Linear decay too noisy | Set `is_stale=True` on events |
| Q8: Asset-Specific Scoping | Report but mark as "not applicable" | Transparency without overwhelming | Add `is_applicable` flag (post-MVP) |
| Q9: Quality Metrics | Proceed without SIEM integration | Simplifies deployment | Health = staleness + syntax + references |
| Q10: Multi-Cloud Normalization | Per-cloud coverage | Users care about per-environment | Coverage per cloud account |

---

## 6. Decision Log

| ID | Date | Decision | Rationale | Alternatives Considered | Impact |
|----|------|----------|-----------|------------------------|--------|
| D1 | 2025-12-18 | GCP first (before Azure) | GCP ~30% of target market; Azure more complex | Azure first, Both parallel | Phase 1 focuses on GCP |
| D2 | 2025-12-18 | Sentence Transformers for NLP | Lightweight, good quality, runs on CPU | OpenAI embeddings, BERT fine-tuned | NLP mapper uses local model |
| D3 | 2025-12-18 | No test triggers for validation | Risk of alert noise; requires staging environment | Test trigger support | Validation is read-only |
| D4 | 2025-12-18 | Metadata-only Lambda parsing | Code analysis complex; metadata provides 60%+ signal | AST parsing, Sandbox execution | Functions mapped via triggers/description |
| D5 | 2025-12-18 | Gap workflow before IaC generation | Tracking is simpler; IaC requires deep cloud expertise | IaC templates first | Remediation = status tracking MVP |
| D6 | 2025-12-18 | Manual MITRE migration script | Migrations infrequent (2x/year); automation complex | Auto-migration on scan | Script + diff report |
| D7 | 2025-12-18 | Defer real-time monitoring | Requires event streaming infrastructure | EventBridge integration | Post-MVP with scheduler polling |
| D8 | 2025-12-18 | Per-cloud coverage (not aggregate) | Users think in terms of accounts/projects | Unified multi-cloud view | Dashboard shows per-account |

---

## 7. Integration Validation Checklist

### After Phase 1 (GCP Support):
- [ ] GCP account can be added via UI
- [ ] GCP service account authentication works
- [ ] All 3 GCP scanners produce `RawDetection` objects
- [ ] Pattern mapper maps GCP detections correctly
- [ ] Coverage snapshot generated for GCP accounts
- [ ] UI displays GCP accounts and coverage

### After Phase 2 (NLP Mapping):
- [ ] NLP mapper loads technique embeddings on startup
- [ ] Hybrid mapper uses pattern first, NLP second
- [ ] `MappingSource` correctly set in database
- [ ] UI shows mapping source for each detection
- [ ] Coverage improves for previously unmapped detections

### After Phase 3 (Health Monitoring):
- [ ] Health validators run during scan
- [ ] Health score persisted on detection model
- [ ] API supports health status filter
- [ ] UI shows health indicators
- [ ] Broken detections excluded from coverage (optional setting)

### After Phase 4 (Enhanced Mapping & Remediation):
- [ ] Lambda functions discovered with trigger metadata
- [ ] Gap status can be updated via API
- [ ] Gap history tracked
- [ ] UI supports gap workflow

### After Phase 5 (MVP Polish):
- [ ] MITRE migration script runs successfully
- [ ] All tests passing
- [ ] Documentation complete
- [ ] No critical bugs

---

## 8. Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| GCP API breaking changes | LOW | MEDIUM | Pin SDK versions; monitor release notes |
| NLP model accuracy issues | MEDIUM | MEDIUM | Conservative confidence; manual review workflow |
| Validation false positives | MEDIUM | LOW | Allow user override; threshold configuration |
| Lambda detection false negatives | HIGH | MEDIUM | Clear documentation; manual mapping option |
| MITRE migration data loss | LOW | HIGH | Backup before migration; diff report review |
| Performance degradation with NLP | MEDIUM | MEDIUM | Async processing; batch embeddings |

---

## 9. Timeline Summary

| Phase | Duration | Start | End | Key Milestone |
|-------|----------|-------|-----|---------------|
| Phase 1: GCP Foundation | 3 weeks | Week 1 | Week 3 | GCP accounts scannable |
| Phase 2: NLP Mapping | 2 weeks | Week 3 | Week 5 | Hybrid mapper live |
| Phase 3: Health Monitoring | 2 weeks | Week 5 | Week 7 | Health scores visible |
| Phase 4: Enhanced Mapping | 2 weeks | Week 7 | Week 9 | Remediation tracking |
| Phase 5: MVP Polish | 2 weeks | Week 9 | Week 11 | MVP complete |

**Total: 11 weeks to MVP completion**

---

## 10. Critical Implementation Files

| Component | File Path | Purpose |
|-----------|-----------|---------|
| Base Scanner | `/backend/app/scanners/base.py` | Interface for GCP scanners |
| Pattern Mapper | `/backend/app/mappers/pattern_mapper.py` | Extend with NLP hybrid |
| Scan Service | `/backend/app/services/scan_service.py` | Add GCP support, health validation |
| Detection Model | `/backend/app/models/detection.py` | Health fields exist |
| Indicator Library | `/backend/app/mappers/indicator_library.py` | Pattern for GCP indicators |

---

## 11. Implementation Status (Updated 2025-12-18)

### Completed Features:

#### Phase 1: GCP Foundation ✅ COMPLETE
- [x] GCP Cloud Logging scanner (`/backend/app/scanners/gcp/cloud_logging_scanner.py`)
- [x] GCP Security Command Center scanner (`/backend/app/scanners/gcp/security_command_center_scanner.py`)
- [x] GCP Eventarc scanner (`/backend/app/scanners/gcp/eventarc_scanner.py`)
- [x] GCP indicator library (`/backend/app/mappers/gcp_indicator_library.py`)

#### Phase 2: NLP Mapping Engine ✅ COMPLETE
- [x] NLP mapper with sentence transformers (`/backend/app/mappers/nlp_mapper.py`)
- [x] Hybrid mapping pipeline (`/backend/app/mappers/hybrid_mapper.py`)
- [x] Confidence calibration between pattern + NLP

#### Phase 3: Detection Health Monitoring ✅ COMPLETE
- [x] Staleness validator (`/backend/app/validators/staleness_validator.py`)
- [x] Syntax validator (`/backend/app/validators/syntax_validator.py`)
- [x] Reference validator (`/backend/app/validators/reference_validator.py`)
- [x] Health calculator (`/backend/app/validators/health_calculator.py`)
- [x] Database migration for health fields (migration 009)

#### Phase 4: Enhanced Mapping & Remediation ✅ COMPLETE
- [x] Lambda scanner enhancement (`/backend/app/scanners/aws/lambda_scanner.py`)
- [x] Gap status model (`/backend/app/models/gap.py`)
- [x] Gap service with full workflow (`/backend/app/services/gap_service.py`)
- [x] Database migration for gap tables (migration 009)

#### Phase 5: MVP Polish & Migration ✅ COMPLETE
- [x] MITRE version migration script (`/backend/app/scripts/migrate_mitre_version.py`)
- [x] Migration diff report generation

### Bonus Feature: Enhanced Code Analysis (Premium) ✅ COMPLETE
- [x] Lambda code parser (`/backend/app/parsers/lambda_code_parser.py`)
- [x] CloudFormation parser (`/backend/app/parsers/cloudformation_parser.py`)
- [x] SDK pattern library with ~50 MITRE mappings (`/backend/app/parsers/sdk_pattern_library.py`)
- [x] Code analysis consent model (`/backend/app/models/code_analysis.py`)
- [x] Code analysis API endpoints (`/backend/app/api/routes/code_analysis.py`)
- [x] Database migration for consent tables (migration 010)
- [x] Full disclosure and IAM policy endpoints
- [x] Opt-in with explicit consent for paying subscribers

### Branding Updates ✅ COMPLETE
- [x] Landing page updated for AWS + GCP support
- [x] Meta descriptions updated
- [x] Pricing tiers reflect multi-cloud

### Remaining Work:

1. **UI Integration**
   - [ ] Health status indicators in detection list
   - [ ] Gap remediation workflow UI
   - [ ] Code analysis consent/enable UI
   - [ ] GCP account connection flow

2. **Testing**
   - [ ] End-to-end tests for GCP scanning
   - [ ] NLP mapper accuracy validation
   - [ ] Health validator unit tests

3. **Documentation**
   - [ ] API documentation for new endpoints
   - [ ] User guide for code analysis feature

---

**Document Version**: 2.0
**Created**: 2025-12-18
**Updated**: 2025-12-18
**Author**: A13E Architecture Team
**Status**: Implementation Complete - UI Integration Pending
