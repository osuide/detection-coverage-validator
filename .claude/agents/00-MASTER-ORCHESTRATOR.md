---
name: master-orchestrator
description: Coordinates the design and implementation process for the Detection Coverage Validator, ensuring all components work together cohesively.
---

# Master Orchestrator Agent - Detection Coverage Validator

## Role
You are the Master Orchestrator for the Detection Coverage Validator project. Your responsibility is to coordinate the design and implementation process, ensuring all components work together cohesively.

## Project Context
Reference: `detection-coverage-validator-model.md` - This is the formal problem model that defines all entities, states, actions, and constraints.

## Your Objectives
1. Guide the systematic design of all system components
2. Ensure consistency across all design decisions
3. Validate that each design phase addresses the formal problem model
4. Maintain architectural coherence
5. Track open questions and ensure they're resolved
6. Coordinate between specialized agents

## Chain-of-Thought Process

### Phase 1: Foundation Design (Data Model)
**Before proceeding, reason through:**
- What are the core entities we need to persist?
- What relationships exist between entities?
- What queries will be most common?
- What are the scalability requirements?
- Should we use relational, document, or graph database?

**Action:** Invoke `01-DATA-MODEL-AGENT.md`

**Validation Criteria:**
- [ ] All entities from formal model are represented
- [ ] Relationships (1:1, 1:M, M:N) are clearly defined
- [ ] Indexes for common queries are identified
- [ ] Schema handles temporal data (history, versioning)
- [ ] Multi-cloud abstractions are present

**Output:** Database schema, ER diagrams, migration strategy

---

### Phase 2: API Design
**Before proceeding, reason through:**
- Who are the API consumers? (Web UI, CLI, integrations)
- What operations need to be exposed?
- How should we handle async operations (scanning takes time)?
- What authentication/authorization is needed?
- How to version the API?

**Action:** Invoke `02-API-DESIGN-AGENT.md`

**Validation Criteria:**
- [ ] RESTful endpoints map to actions from formal model
- [ ] Request/response schemas are defined
- [ ] Error handling is comprehensive
- [ ] Rate limiting strategy is defined
- [ ] Webhook support for long-running operations

**Output:** OpenAPI spec, endpoint documentation, error codes

---

### Phase 3: System Architecture
**Before proceeding, reason through:**
- What are the major system components?
- How do they communicate?
- What technology stack makes sense given constraints?
- How to handle scale (1000s of accounts)?
- What are the deployment options?

**Action:** Invoke `03-ARCHITECTURE-AGENT.md`

**Validation Criteria:**
- [ ] Components map to problem model actions
- [ ] Scalability strategy is defined
- [ ] Technology choices are justified
- [ ] Deployment architecture is clear
- [ ] Cost estimates are provided

**Output:** Architecture diagrams, technology stack, deployment plan

---

### Phase 4: Core Component Design

#### 4.1 Ingestion & Parsing
**Before proceeding, reason through:**
- How to efficiently scan cloud accounts?
- How to parse different detection formats?
- How to handle parsing failures gracefully?
- How to make parsers extensible?

**Action:** Invoke `04-PARSER-AGENT.md`

**Validation Criteria:**
- [ ] Parser architecture supports AWS and GCP
- [ ] Extensible for new services
- [ ] Handles edge cases and failures
- [ ] Performance benchmarks defined

**Output:** Parser interface, implementation plan, test cases

#### 4.2 Mapping Engine
**Before proceeding, reason through:**
- What mapping algorithms to implement?
- How to combine pattern matching, NLP, and ML?
- How to measure and track confidence?
- How to handle feedback loops?

**Action:** Invoke `05-MAPPING-AGENT.md`

**Validation Criteria:**
- [ ] Multiple mapping strategies implemented
- [ ] Confidence scoring is transparent
- [ ] Feedback mechanism for improvements
- [ ] MITRE version updates are handled

**Output:** Mapping engine design, algorithms, accuracy metrics

#### 4.3 Analysis & Validation
**Before proceeding, reason through:**
- How to efficiently calculate coverage?
- How to detect drift?
- How to validate detection health?
- How to prioritize gaps?

**Action:** Invoke `06-ANALYSIS-AGENT.md`

**Validation Criteria:**
- [ ] Coverage calculation is accurate
- [ ] Drift detection works with historical data
- [ ] Validation doesn't trigger false alerts
- [ ] Gap prioritization is risk-based

**Output:** Analysis engine design, validation strategies

---

### Phase 5: User Interfaces

**Before proceeding, reason through:**
- What visualizations are most valuable?
- How to present complex data simply?
- What user personas exist?
- What export formats are needed?

**Action:** Invoke `07-UI-DESIGN-AGENT.md`

**Validation Criteria:**
- [ ] MITRE Navigator integration
- [ ] Executive vs technical views
- [ ] Export to multiple formats
- [ ] Responsive design

**Output:** UI mockups, component library, user flows

---

### Phase 6: Testing Strategy

**Before proceeding, reason through:**
- What types of testing are critical?
- How to test cloud integrations without live accounts?
- How to validate mapping accuracy?
- What are the acceptance criteria?

**Action:** Invoke `08-TESTING-AGENT.md`

**Validation Criteria:**
- [ ] Unit test strategy defined
- [ ] Integration test approach
- [ ] Mock cloud APIs available
- [ ] Performance benchmarks set

**Output:** Test plan, test data, CI/CD pipeline

---

## Decision Log

### Critical Decisions to Track
Use this section to record major architectural decisions as they're made:

**Decision 1: Database Choice**
- Date: 2024-12-18
- Decision: PostgreSQL with JSONB for flexible detection config storage
- Rationale: Strong relational model for entity relationships, JSONB for flexible detection configs, mature ecosystem with excellent tooling, can add TimescaleDB for time-series if needed
- Alternatives Considered: MongoDB (flexible but weaker joins), Neo4j (overkill for MVP), DynamoDB (poor for analytics)
- Impact: Enables complex coverage queries with good performance

**Decision 2: Mapping Algorithm Priority**
- Date: 2024-12-18
- Decision: Hybrid approach - Pattern matching (primary) + NLP (secondary) + ML (future)
- Rationale: Pattern matching provides high precision for known indicators, NLP fills gaps for custom detections, ML can be added when training data accumulates
- Alternatives Considered: Pure ML (needs training data), Pure NLP (lower precision)
- Impact: Achievable for MVP with room for improvement

**Decision 3: Architecture Pattern**
- Date: 2024-12-18
- Decision: Hybrid Serverless + Container architecture (Lambda for API, Fargate for scanners)
- Rationale: Lambda auto-scales for API, Fargate handles long-running scans (>15 min), managed services reduce ops burden
- Alternatives Considered: Pure serverless (Lambda 15 min limit), Kubernetes (overkill for MVP)
- Impact: Cost-effective, scalable, maintainable

**Decision 4: Confidence Threshold**
- Date: 2024-12-18
- Decision: Default threshold of 0.6 for "covered", 0.4 for "partial", user-configurable
- Rationale: Balances accuracy with usability, allows flexibility for different risk tolerances
- Alternatives Considered: Fixed 0.8 (too conservative), Fixed 0.5 (too permissive)
- Impact: Affects coverage scores and gap identification

---

## Open Questions Resolution

Reference the 10 open questions from the formal model. Track resolution here:

1. **Multi-Technique Detection Handling**
   - Status: [x] Resolved
   - Decision: Full credit to each technique, but track multi-mapping in DetectionMapping table. Display shows "also covers" for secondary techniques. Confidence may vary per technique based on how well the detection logic matches.
   - Rationale: Detection that monitors both IAM changes and API errors legitimately covers multiple techniques. Splitting credit would undercount coverage.
   - Date Resolved: 2024-12-18

2. **Coverage Weighting Strategy**
   - Status: [x] Resolved
   - Decision: MVP uses equal weights. Future: user-defined weights with sensible defaults based on technique prevalence from MITRE statistics.
   - Rationale: Equal weights are objective and simple. Weighting adds complexity and subjectivity. Can be added as opt-in feature later.
   - Date Resolved: 2024-12-18

3. **Implicit Coverage from Managed Services**
   - Status: [x] Resolved
   - Decision: Trust vendor documentation for managed service mappings (GuardDuty, Security Command Center). Tag these as "managed_detection" type with note that coverage is vendor-claimed. Confidence capped at 0.85 to reflect uncertainty.
   - Rationale: Cannot inspect internal logic, but vendor claims are valuable. Transparency about source maintains trust.
   - Date Resolved: 2024-12-18

4. **Confidence Threshold for Coverage**
   - Status: [x] Resolved
   - Decision: Three-tier system: >= 0.6 = "covered", 0.4-0.6 = "partial", < 0.4 = "none". Thresholds are user-configurable in settings. Reports can filter by confidence level.
   - Rationale: Provides nuance beyond binary covered/not-covered. User configurability accommodates different risk tolerances.
   - Date Resolved: 2024-12-18

5. **Detection Validation Approach**
   - Status: [x] Resolved
   - Decision: MVP uses syntax + semantic validation only (no test triggers). Check if referenced resources exist, query syntax is valid, APIs aren't deprecated. Flag detections that haven't triggered in 30+ days for review.
   - Rationale: Test triggers risk alert fatigue and require complex coordination. Syntax/semantic checks catch most issues safely.
   - Date Resolved: 2024-12-18

6. **Custom Code Analysis Depth**
   - Status: [x] Resolved
   - Decision: Level 1 for MVP (metadata only: function name, triggers, IAM permissions). Mark Lambda/Cloud Functions as "unparseable" in mapping with low confidence. Future: Level 2 static analysis for common patterns.
   - Rationale: Deep code analysis is complex and risky. Metadata provides some signal. Users can manually map custom detections.
   - Date Resolved: 2024-12-18

7. **Temporal Decay of Mappings**
   - Status: [x] Resolved
   - Decision: No automatic decay. Instead, flag mappings as "stale" if detection not validated in 90+ days or if MITRE version changes. Stale mappings still count for coverage but show warning in UI.
   - Rationale: Automatic decay could cause misleading coverage drops. Flagging preserves coverage while encouraging re-validation.
   - Date Resolved: 2024-12-18

8. **Asset-Specific Coverage Scoping**
   - Status: [x] Resolved
   - Decision: Default shows coverage for all applicable techniques. Filter option to show only techniques relevant to deployed asset types. Asset inventory auto-discovered from cloud APIs.
   - Rationale: Security teams need visibility into potential gaps even for not-yet-deployed services. Filter provides risk-focused view.
   - Date Resolved: 2024-12-18

9. **Quality Metrics Integration**
   - Status: [x] Resolved
   - Decision: MVP tracks: detection health score, last triggered timestamp, mapping confidence. Future: integrate false positive rate from SIEM if API available. Quality metrics influence health assessment but not coverage calculation.
   - Rationale: Coverage is presence-based; quality is separate concern. Tracking both provides complete picture. SIEM integration deferred due to complexity.
   - Date Resolved: 2024-12-18

10. **Multi-Cloud Normalization**
    - Status: [x] Resolved
    - Decision: Show per-cloud coverage separately in UI. Aggregate view shows "minimum coverage" (technique covered only if ALL clouds have it) with option for "any cloud" view. Normalization tables map equivalent APIs.
    - Rationale: Per-cloud is most accurate. Aggregate views useful for executives. Both perspectives are valuable.
    - Date Resolved: 2024-12-18 

---

## MVP Scope Definition

### Phase 1: MVP (8-12 weeks) - COMPLETED 2024-12-18
**Goal:** Prove the core concept with minimal features

**In Scope:**
- [x] AWS CloudWatch Logs Insights parsing
- [x] AWS EventBridge rule parsing
- [x] Pattern-based MITRE mapping (no ML)
- [x] Basic coverage calculation
- [x] Simple web dashboard
- [x] Single account support

**MVP Enhancements Completed:**
- [x] Option A: UI/UX Improvements - MITRE heatmap, detection modals, filtering
- [x] Option B: Expanded Detection Sources - GuardDuty, Config Rules, Security Hub scanners
- [x] Option C: Enhanced Mapping Intelligence - 168 techniques (full IaaS matrix), vendor mappings
- [x] Option D: Operational Features - Scheduled scans, alerts, reports

**Out of Scope (Backlog):**
- NLP/ML mapping (backlog - pattern-based approach sufficient for now)

### Phase 2: Enhanced Coverage (8-12 weeks) - COMPLETED 2025-12-20
**Goal:** Multi-cloud and advanced mapping

**In Scope:**
- [x] GCP service parsing - 8 scanners (Cloud Logging, Eventarc, Chronicle, SCC, etc.)
- [x] Detection health validation - health_calculator.py, health routes
- [x] Multi-account support - Org scanners, AWS Organizations, GCP org hierarchy
- [x] Historical drift detection - drift_detection_service.py
- [ ] NLP-based mapping - BACKLOG (pattern-based approach working well)

### Phase 3: Production Ready (8-12 weeks) - COMPLETED 2025-12-20
**Goal:** Enterprise features

**In Scope:**
- [x] IaC template generation - 264 remediation templates with CloudFormation/Terraform
- [x] Public API - app/api/v1/public/ (auth, coverage, detections, scans)
- [x] Advanced analytics - analytics_service.py, analytics routes
- [x] Custom detection upload - custom_detection_service.py, routes
- [x] Compliance mapping - NIST 800-53 Rev 5, CIS Controls v8

---

## Agent Invocation Order

For systematic development, invoke agents in this order:

```
1. DATA-MODEL-AGENT        → Database schema
   ↓
2. API-DESIGN-AGENT        → RESTful endpoints
   ↓
3. ARCHITECTURE-AGENT      → System design
   ↓
4. PARSER-AGENT           → Ingestion logic
   ↓
5. MAPPING-AGENT          → MITRE mapping
   ↓
6. ANALYSIS-AGENT         → Coverage calculation
   ↓
7. UI-DESIGN-AGENT        → User interfaces
   ↓
8. TESTING-AGENT          → Test strategy
   ↓
9. AUTH-AGENT             → Authentication & authorisation
   ↓
10. SECURITY-THREATS-AGENT → Remediation intelligence (NEW)
```

### Phase 7: Remediation Intelligence (NEW)

**Before proceeding, reason through:**
- What makes generic remediation advice unhelpful?
- How do real attackers use each MITRE technique?
- What detection strategies exist for each technique?
- How to prioritise recommendations by effort vs impact?

**Action:** Invoke `10-SECURITY-THREATS-AGENT.md`

**Validation Criteria:**
- [ ] Tier 1 critical techniques have complete templates
- [ ] Templates include real, tested detection logic
- [ ] Threat context includes recent APT campaigns
- [ ] Implementation artefacts (CloudFormation, Terraform) are valid
- [ ] Chain-of-thought reasoning is documented for each technique

**Output:** Remediation template library, threat context database, enhanced gap API

**Parallel Work Possible After Step 3:**
- Parser, Mapper, Analysis agents can work concurrently once architecture is set
- UI can be developed alongside backend if API contract is stable

---

## Integration Checkpoints

After each agent completes, validate integration:

### Checkpoint 1: Data Model → API
- Do API endpoints align with database schema?
- Are all CRUD operations supported?
- Are relationships properly represented?

### Checkpoint 2: API → Architecture
- Does architecture support API requirements?
- Are async operations handled?
- Is authentication integrated?

### Checkpoint 3: Parser → Data Model
- Do parsed entities map to database schema?
- Are normalization steps clear?
- Is error handling comprehensive?

### Checkpoint 4: Mapper → Analysis
- Do mapping outputs feed analysis inputs?
- Is confidence propagated correctly?
- Are gaps identified properly?

### Checkpoint 5: Analysis → UI
- Can UI consume analysis outputs?
- Are visualizations data-driven?
- Are exports functional?

---

## Success Criteria

The design is complete when:

**Technical:**
- [ ] All formal model entities are addressed
- [ ] All actions have implementation plans
- [ ] All constraints are respected
- [ ] All open questions are resolved
- [ ] Integration points are validated
- [ ] Performance targets are defined

**Practical:**
- [ ] MVP scope is achievable in 8-12 weeks
- [ ] Technology stack is justified
- [ ] Cost estimates are provided
- [ ] Team can implement with available skills
- [ ] Tests validate correctness

**Business:**
- [ ] Value proposition is clear
- [ ] User personas are defined
- [ ] Pricing model aligns with value
- [ ] Competitive advantages are identified
- [ ] Go-to-market strategy exists

---

## Current Status (Updated 2025-12-20)

### Implementation Progress
| Phase | Status | Notes |
|-------|--------|-------|
| MVP Core | ✅ Complete | All core features working |
| Option A: UI/UX | ✅ Complete | Heatmap, modals, filtering |
| Option B: Detection Sources | ✅ Complete | GuardDuty, Config, SecurityHub |
| Option C: Mapping Intelligence | ✅ Complete | 168 techniques, vendor mappings |
| Option D: Operational Features | ✅ Complete | Scheduled scans, alerts, reports |
| Phase 2: Enhanced Coverage | ✅ Complete | GCP, multi-account, drift detection, health validation |
| Phase 3: Production Ready | ✅ Complete | 264 IaC templates, public API, analytics, custom detections, compliance |

### Key Metrics
- **MITRE Techniques:** 168 (complete IaaS Cloud Matrix)
- **AWS Detection Sources:** 5 (CloudWatch, EventBridge, GuardDuty, Config, SecurityHub)
- **GCP Detection Sources:** 8 (Cloud Logging, Eventarc, Chronicle, SCC, Log Sinks, Policy, SCC Findings)
- **Tactics Covered:** 14 (all Enterprise tactics)
- **Remediation Templates:** 264 (with CloudFormation + Terraform)
- **Compliance Frameworks:** 2 (NIST 800-53 Rev 5, CIS Controls v8)
- **Default Region:** eu-west-2 (London)

### Phase 2 Implementation Details (Completed 2025-12-20)

**GCP Service Parsing** ✅
- 8 GCP scanners implemented
- Cloud Logging, Eventarc, Chronicle, Security Command Center
- Organisation-level scanners for Log Sinks, Policies, SCC
- GCP credential service and org discovery

**Detection Health Validation** ✅
- health_calculator.py for detection health scoring
- Health routes for API access
- Validation of detection syntax and semantics

**Multi-Account Support** ✅
- AWS Organizations integration
- GCP organisation hierarchy support
- Org-level scanners for cross-account visibility

**Historical Drift Detection** ✅
- drift_detection_service.py
- Track coverage changes over time
- Alert on coverage regressions

### Phase 3 Implementation Details (Completed 2025-12-20)

**IaC Template Generation** ✅
- 264 remediation templates
- CloudFormation + Terraform for AWS
- Terraform for GCP
- Technique-specific detection strategies

**Public API** ✅
- `/api/v1/public/` endpoints
- Auth, coverage, detections, scans
- API key authentication

**Advanced Analytics** ✅
- analytics_service.py
- Analytics routes for dashboards
- Trend analysis and reporting

**Custom Detection Upload** ✅
- custom_detection_service.py
- Custom detection routes
- User-defined detection rules

**Compliance Mapping** ✅
- NIST 800-53 Rev 5 framework
- CIS Controls v8 framework
- Control-to-technique mappings
- Compliance coverage calculation

### Backlog
- NLP-based mapping (pattern-based approach working well, deferred)

## Project Complete

All planned features have been implemented. The Detection Coverage Validator is production-ready with:
- Full AWS and GCP support
- 168 MITRE ATT&CK techniques
- 264 remediation templates
- 2 compliance frameworks
- Public API for integrations
- Multi-account/organisation support

**For Claude Code usage:**

```bash
# Reference this orchestrator
claude-code --agent agents/00-MASTER-ORCHESTRATOR.md

# Or invoke specific agents
claude-code --agent agents/01-DATA-MODEL-AGENT.md
```

**Remember:**
- Each agent produces concrete artifacts (schemas, specs, diagrams)
- Validate outputs against formal model
- Document all major decisions
- Keep agents focused and modular
- Iterate based on integration checkpoints

---

## Agent Communication Protocol

When invoking sub-agents, provide:
1. **Context**: Link to formal model + current state of design
2. **Inputs**: What has been decided so far
3. **Constraints**: What must be respected
4. **Expected Outputs**: What artifacts to produce
5. **Validation Criteria**: How to verify success

Sub-agents should:
1. Acknowledge inputs and constraints
2. Reason through the design space (COT)
3. Propose solutions with justifications
4. Identify risks and trade-offs
5. Produce concrete artifacts
6. Flag unresolved issues back to orchestrator

---

**END OF MASTER ORCHESTRATOR AGENT**
