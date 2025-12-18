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
- [ ] Option D: Operational Features - Scheduled scans, alerts, reports (NEXT)

**Out of Scope (Future):**
- GCP support (phase 2)
- NLP/ML mapping (phase 2)
- Detection health validation (phase 2)
- Multi-account organizations (phase 2)
- IaC generation (phase 3)
- API for integrations (phase 3)

### Phase 2: Enhanced Coverage (8-12 weeks)
**Goal:** Multi-cloud and advanced mapping

**In Scope:**
- [ ] GCP service parsing
- [ ] NLP-based mapping
- [ ] Detection health validation
- [ ] Multi-account support
- [ ] Historical drift detection

### Phase 3: Production Ready (8-12 weeks)
**Goal:** Enterprise features

**In Scope:**
- [ ] IaC template generation
- [ ] Public API
- [ ] Advanced analytics
- [ ] Custom detection upload
- [ ] Compliance mapping

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
```

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

## Current Status (Updated 2024-12-18)

### Implementation Progress
| Phase | Status | Notes |
|-------|--------|-------|
| MVP Core | ✅ Complete | All core features working |
| Option A: UI/UX | ✅ Complete | Heatmap, modals, filtering |
| Option B: Detection Sources | ✅ Complete | GuardDuty, Config, SecurityHub |
| Option C: Mapping Intelligence | ✅ Complete | 168 techniques, vendor mappings |
| Option D: Operational Features | 🔄 Next | Scheduled scans, alerts, reports |

### Key Metrics
- **MITRE Techniques:** 168 (complete IaaS Cloud Matrix)
- **Detection Sources:** 5 (CloudWatch, EventBridge, GuardDuty, Config, SecurityHub)
- **Tactics Covered:** 14 (all Enterprise tactics)
- **Default Region:** eu-west-2 (London)

### Next Step: Option D - Operational Features
Implement the following:

**D.1: Scheduled Scans**
- Add cron-based scan scheduling (daily/weekly/custom)
- Use Celery or APScheduler for task scheduling
- Store schedule config per cloud account

**D.2: Alerts & Notifications**
- Coverage threshold alerts (email/webhook)
- Scan completion notifications
- Gap detection alerts
- Stale detection warnings

**D.3: Reports**
- PDF/CSV export of coverage reports
- Executive summary generation
- Trend analysis reports
- Gap remediation recommendations

## Next Steps

**To begin the design process:**

1. Review the formal problem model thoroughly
2. Start with the Data Model Agent (01-DATA-MODEL-AGENT.md)
3. Work through each agent sequentially
4. Update this document with decisions and resolutions
5. Maintain consistency across all design artifacts

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
