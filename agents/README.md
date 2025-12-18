# Detection Coverage Validator - COT Agent Framework

## Overview

This directory contains a Chain-of-Thought (COT) driven agent framework for designing and implementing the Detection Coverage Validator system. Each agent is a specialized markdown document that guides systematic reasoning through a specific aspect of the system design.

---

## Current Implementation Status (Updated 2025-12-18)

> **See `ROADMAP.md` for detailed phase plan and `MVP-STATUS.md` for current progress.**

### Phase 0: MVP Launch - IN PROGRESS 🔴
**Focus:** Get to revenue-generating state

| Task | Status | Priority |
|------|--------|----------|
| Stripe Integration | ⏳ TODO | CRITICAL |
| Staging Environment | ⏳ TODO | CRITICAL |
| Real AWS Scanning | ⏳ TODO | CRITICAL |
| OAuth Providers | ⏳ TODO | HIGH |
| Email Service | ⏳ TODO | HIGH |
| Basic Tests | ⏳ TODO | MEDIUM |

**DO NOT work on Phase 1+ until Phase 0 is complete.**

### What's Already Done ✅
- Data Model (Agent 01) - Complete
- API Design (Agent 02) - Complete
- Architecture (Agent 03) - Complete (local dev)
- Parser Design (Agent 04) - Complete (AWS + GCP scanners)
- Mapping Engine (Agent 05) - Complete (pattern matching)
- Analysis Engine (Agent 06) - Complete (coverage + gaps)
- UI Design (Agent 07) - Complete (all pages)

### What's Deferred to Later Phases
- Detection Validation → Phase 1
- Scheduled Scans → Phase 1
- Drift Detection → Phase 1
- NLP/ML Mapping → Phase 2
- IaC Generation → Phase 3

---

## What This Framework Provides

**Instead of jumping straight to code**, this framework ensures:
- ✅ Systematic exploration of design space
- ✅ Documented reasoning for all major decisions
- ✅ Validation of design against problem model
- ✅ Reusable artifacts (schemas, specs, diagrams)
- ✅ Consistency across all system components

## Agent Hierarchy

```
00-MASTER-ORCHESTRATOR.md
├── 01-DATA-MODEL-AGENT.md          (Database schema design)
├── 02-API-DESIGN-AGENT.md          (RESTful API endpoints)
├── 03-ARCHITECTURE-AGENT.md        (System architecture)
├── 04-PARSER-AGENT.md              (Detection parsing logic)
├── 05-MAPPING-AGENT.md             (MITRE mapping engine)
├── 06-ANALYSIS-AGENT.md            (Coverage calculation)
├── 07-UI-DESIGN-AGENT.md           (User interfaces)
└── 08-TESTING-AGENT.md             (Test strategy)
```

## How to Use This Framework

### Method 1: With Claude Code (Recommended)

```bash
# Start with the orchestrator
claude-code --agent agents/00-MASTER-ORCHESTRATOR.md

# Or invoke specific agents directly
claude-code --agent agents/01-DATA-MODEL-AGENT.md

# For multi-turn design sessions
claude-code --session design-session \
  --agent agents/00-MASTER-ORCHESTRATOR.md \
  --context detection-coverage-validator-model.md
```

### Method 2: With Claude Chat (Interactive)

1. Open Claude chat interface
2. Upload `detection-coverage-validator-model.md` for context
3. Copy-paste agent content into chat
4. Work through the agent's reasoning process interactively
5. Save outputs as instructed

### Method 3: Manual Design Process

1. Read the formal problem model thoroughly
2. Work through each agent sequentially
3. Document your reasoning at each step
4. Produce the specified artifacts
5. Validate against the problem model
6. Update the orchestrator with decisions

## Agent Invocation Order

**Phase 1: Foundation (Sequential)**
```
1. Master Orchestrator → Review overall strategy
2. Data Model Agent    → Design database schema
3. API Design Agent    → Design RESTful endpoints
4. Architecture Agent  → Design system components
```

**Phase 2: Components (Can be parallel after Architecture)**
```
5. Parser Agent        → Design detection ingestion
6. Mapping Agent       → Design MITRE mapping
7. Analysis Agent      → Design coverage calculation
```

**Phase 3: User-Facing (After core components)**
```
8. UI Design Agent     → Design dashboards
9. Testing Agent       → Design test strategy
```

## What Each Agent Does

### 00-MASTER-ORCHESTRATOR
**Purpose:** Coordinates entire design process  
**Inputs:** Formal problem model  
**Outputs:** 
- Decision log
- Open question resolutions
- Integration validation
- MVP scope definition

**Key Questions:**
- What's the MVP scope?
- Which open questions need resolution first?
- How do components integrate?

---

### 01-DATA-MODEL-AGENT
**Purpose:** Design database schema  
**Inputs:** Problem model entities and state variables  
**Outputs:**
- Complete SQL schema (or NoSQL schema)
- ER diagram
- Data dictionary
- Query patterns
- Migration strategy

**Key Questions:**
- Relational vs document vs graph database?
- How to model M:N relationships?
- How to handle temporal data (history)?
- What indexes for performance?

---

### 02-API-DESIGN-AGENT
**Purpose:** Design RESTful API  
**Inputs:** Problem model actions, database schema  
**Outputs:**
- OpenAPI 3.0 specification
- API documentation
- Postman collection
- Rate limiting strategy
- Webhook specs

**Key Questions:**
- How to handle async operations?
- What authentication mechanism?
- How to version the API?
- What error codes to use?

---

### 03-ARCHITECTURE-AGENT
**Purpose:** Design system architecture  
**Inputs:** API spec, scale requirements, constraints  
**Outputs:**
- Architecture diagrams
- Technology stack justification
- Deployment plan
- Scaling strategy
- Cost estimates

**Key Questions:**
- Monolith vs microservices?
- Which cloud services to use?
- How to handle scale (1000s of accounts)?
- What deployment model (serverless vs containers)?

---

### 04-PARSER-AGENT
**Purpose:** Design detection parsing logic  
**Inputs:** Cloud service APIs, detection formats  
**Outputs:**
- Parser interface design
- Implementation plan for AWS/GCP
- Error handling strategy
- Test cases

**Key Questions:**
- How to parse different detection formats?
- How to make parsers extensible?
- How to handle parsing failures?
- How to normalize across clouds?

---

### 05-MAPPING-AGENT
**Purpose:** Design MITRE mapping engine  
**Inputs:** Parsed detections, MITRE framework  
**Outputs:**
- Mapping algorithm design
- Confidence scoring methodology
- Pattern library
- ML model architecture (if using ML)

**Key Questions:**
- Pattern matching vs NLP vs ML?
- How to measure confidence?
- How to handle feedback loops?
- How to update when MITRE changes?

---

### 06-ANALYSIS-AGENT
**Purpose:** Design coverage calculation and validation  
**Inputs:** Mapped detections, account assets  
**Outputs:**
- Coverage calculation algorithm
- Gap identification logic
- Drift detection strategy
- Validation approach

**Key Questions:**
- How to calculate coverage scores?
- How to detect drift over time?
- How to validate without triggering alerts?
- How to prioritize gaps by risk?

---

### 07-UI-DESIGN-AGENT
**Purpose:** Design user interfaces  
**Inputs:** API endpoints, user personas  
**Outputs:**
- UI mockups
- Component library
- User flows
- Visualization strategies

**Key Questions:**
- What visualizations are most valuable?
- How to present to different personas?
- What export formats needed?
- Mobile vs desktop focus?

---

### 08-TESTING-AGENT
**Purpose:** Design testing strategy  
**Inputs:** All system components  
**Outputs:**
- Test plan
- Unit test strategy
- Integration test approach
- Performance benchmarks
- CI/CD pipeline

**Key Questions:**
- How to test cloud integrations?
- How to validate mapping accuracy?
- What are acceptance criteria?
- How to mock external APIs?

---

## Agent Output Structure

Each agent produces:

1. **Reasoning Document** (markdown)
   - Chain-of-thought exploration
   - Design alternatives considered
   - Rationale for decisions
   - Trade-offs analyzed

2. **Concrete Artifacts**
   - Schemas, specs, diagrams
   - Code templates
   - Test cases
   - Documentation

3. **Integration Notes**
   - How this component connects to others
   - Dependencies required
   - Assumptions made
   - Open issues flagged

4. **Validation Checklist**
   - Criteria for success
   - What to validate
   - How to validate

## Design Principles

### 1. Chain-of-Thought Reasoning
Agents explicitly reason through:
- "What are the options?"
- "What are the trade-offs?"
- "What do we optimize for?"
- "Why this choice over alternatives?"

### 2. Problem Model Driven
Every design decision traces back to:
- An entity from the problem model
- An action that needs support
- A constraint that must be respected

### 3. Validation at Every Step
Before moving forward:
- Validate against problem model
- Check integration with previous components
- Identify risks and mitigation strategies

### 4. Concrete Artifacts
Don't just describe - produce:
- Runnable SQL schemas
- Valid OpenAPI specs
- Deployable architecture diagrams
- Executable test cases

### 5. Iterative Refinement
Agents can be re-run with updated context:
- When open questions are resolved
- When requirements change
- When new constraints emerge

## Integration Checkpoints

After each agent, validate:

**After Data Model:**
- Can the schema represent all entities?
- Are queries efficient?
- Does it support all actions?

**After API Design:**
- Do endpoints map to database operations?
- Are async operations handled?
- Is authentication integrated?

**After Architecture:**
- Can architecture support API requirements?
- Do technology choices align with constraints?
- Is deployment feasible?

**After Parsers/Mappers/Analysis:**
- Do components integrate with data model?
- Are APIs sufficient for component needs?
- Are error cases handled?

**After UI/Testing:**
- Can UI consume API endpoints?
- Are tests comprehensive?
- Is system ready for deployment?

## Decision Documentation

The Master Orchestrator maintains:

### Decision Log
Record major architectural decisions:
- What was decided
- When
- Why (rationale)
- Alternatives considered
- Impact on system

### Open Questions Tracker
Track resolution of 10 open questions from problem model:
- Current status (open/in discussion/resolved)
- Decision made
- Date resolved
- Impact on design

### Integration Matrix
Track dependencies between components:
```
Component A → Depends on → Component B
Parser      → Depends on → Data Model (detection schema)
API         → Depends on → Parser (detection endpoints)
Analysis    → Depends on → Mapper (coverage calculation)
```

## MVP Scope Management

The orchestrator defines what's in/out of scope for MVP:

**MVP Phase 1 (8-12 weeks):**
- Core functionality only
- AWS support (GCP in phase 2)
- Pattern-based mapping (ML in phase 2)
- Basic dashboard (advanced viz in phase 3)

**Why this matters:**
- Keeps agents focused on essentials
- Prevents over-engineering
- Enables faster validation
- Allows iterative improvement

## Tips for Effective Use

### 1. Start with Problem Model
Always have `detection-coverage-validator-model.md` open as reference.

### 2. Work Sequentially (Initially)
Don't skip agents - each builds on the previous.

### 3. Document Decisions
Use the orchestrator's decision log religiously.

### 4. Iterate When Needed
If later agents reveal issues, revisit earlier ones.

### 5. Produce Real Artifacts
Don't just describe the schema - write actual SQL.
Don't just explain the API - write OpenAPI spec.

### 6. Validate Frequently
Check integration points after each agent.

### 7. Flag Issues Early
If an agent reveals a problem, flag it to orchestrator immediately.

## Example Usage Session

```bash
# Session 1: Foundation
$ claude-code --agent agents/00-MASTER-ORCHESTRATOR.md
> Review problem model
> Define MVP scope
> Set up decision log

$ claude-code --agent agents/01-DATA-MODEL-AGENT.md
> Design PostgreSQL schema
> Create ER diagram
> Define indexes
> Write migration files

$ claude-code --agent agents/02-API-DESIGN-AGENT.md
> Design RESTful endpoints
> Write OpenAPI spec
> Define error codes
> Create Postman collection

# Session 2: Architecture & Core Components
$ claude-code --agent agents/03-ARCHITECTURE-AGENT.md
> Design serverless architecture
> Choose AWS services
> Plan deployment
> Estimate costs

$ claude-code --agent agents/04-PARSER-AGENT.md
> Design CloudWatch parser
> Design EventBridge parser
> Plan GCP parsers (phase 2)
> Write test cases

# Session 3: Advanced Features
$ claude-code --agent agents/05-MAPPING-AGENT.md
> Design pattern matching engine
> Plan NLP integration (phase 2)
> Define confidence scoring
> Create pattern library

# ... continue through remaining agents
```

## Troubleshooting

### "Agent reasoning is too abstract"
→ Demand concrete artifacts. Ask: "Show me the actual SQL/code/spec"

### "Agents making inconsistent decisions"
→ Update orchestrator's decision log. Ensure all agents reference it.

### "Agent skipping important considerations"
→ Reference the formal problem model explicitly. Point to relevant sections.

### "Design doesn't handle edge case X"
→ Add to constraints in problem model, re-run affected agents.

### "Not sure which agent to run next"
→ Follow the orchestrator's recommended sequence.

## Success Criteria

The design is complete when:

**Technical:**
- [ ] All entities from problem model have schema
- [ ] All actions have API endpoints
- [ ] All constraints are addressed
- [ ] All open questions resolved
- [ ] Integration validated at each checkpoint

**Practical:**
- [ ] Artifacts are concrete and implementable
- [ ] Technology stack is justified
- [ ] Cost estimates provided
- [ ] MVP scope is achievable

**Documented:**
- [ ] All major decisions logged
- [ ] All artifacts produced
- [ ] All validation checklists completed
- [ ] All integration points verified

## Next Steps After Design

Once all agents complete:

1. **Review & Validate**
   - Walk through entire design
   - Check for inconsistencies
   - Validate against problem model

2. **Implementation Planning**
   - Break into implementation tasks
   - Assign priorities
   - Set milestones

3. **Begin Implementation**
   - Start with data model (database setup)
   - Implement core API endpoints
   - Build parsers and mappers
   - Develop UI
   - Write tests

4. **Iterate**
   - Re-run agents as needed
   - Update based on implementation learnings
   - Refine based on user feedback

---

## Questions?

If you encounter issues using this framework:
1. Check the formal problem model for clarity
2. Review the orchestrator for guidance
3. Ensure you're following the recommended sequence
4. Validate integration checkpoints

Remember: **These agents are tools for systematic thinking, not rigid scripts.** Adapt them to your needs, but maintain the core principle: explicit reasoning before implementation.

---

**Happy designing! 🚀**
