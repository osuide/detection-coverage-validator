# Support System Backlog

This document tracks completed features and future enhancements for the A13E Support System.

**Last Updated:** January 2026

---

## Phase 1: Core Infrastructure (COMPLETED)

- [x] **Google Groups Collaborative Inbox:** Created support@a13e.com
- [x] **Gmail Labels:** Automated category, priority, tier, and status labels
- [x] **Google Sheets CRM:** Ticket logging with customer context
- [x] **Apps Script Automation:** Email processing every 5 minutes
- [x] **Claude AI Integration:** Automatic classification and draft generation
- [x] **Backend Customer Context API:** `/api/support/customer-context` endpoint

---

## Phase 2: Production Hardening (COMPLETED)

- [x] **Environment-Aware URLs:** Script detects staging vs production from API response
- [x] **Tier Display:** Uses `tier_display` field for human-readable tier names
- [x] **Accurate Gap Count:** Uses `uncovered_techniques` from CoverageSnapshot (not CoverageGap table)
- [x] **Unknown Customer Handling:** Graceful handling with production URL defaults
- [x] **SUPPORT_API_KEY Persistence:** Unconditional inclusion in ECS task definition
- [x] **Draft Header Simplification:** Removed AI warning text, kept customer context only
- [x] **Legacy Tier Support:** Indicates when customer is on legacy pricing
- [x] **Rate Limiting:** Protection against API quota exhaustion
- [x] **Prompt Injection Protection:** Input sanitisation and security monitoring
- [x] **Auto-Suspension:** Blocks repeated malicious attempts

---

## Phase 3: Knowledge Base Integration (COMPLETED)

**Goal:** Enable the AI agent to provide more detailed, technically accurate answers by searching a repository of documentation rather than relying solely on its training data.

- [x] **Create Document Repository:** Set up a dedicated folder in Google Drive (`A13E Operations/Knowledge Base`) with subfolders for User Guide and API Guides
- [x] **Implement Search Logic:** `KnowledgeBase.gs` implements:
    1.  Extracts meaningful search terms from user queries (filters stop words)
    2.  Recursively searches KB folder for matching markdown/text files
    3.  Calculates relevance scores (filename, content, heading matches)
    4.  Extracts most relevant sections from matching documents
- [x] **RAG Pattern Integration:** Adds `<knowledge_base_context>` section to Claude prompt with relevant documentation
- [x] **Category-Based Prioritisation:** Searches prioritise folders based on ticket category (e.g., billing → User Guide)

**New Script Property Required:** `KB_FOLDER_ID` - Google Drive folder ID containing documentation

---

## Phase 4: SLA Management & Auto-Send (COMPLETED)

**Goal:** Ensure timely responses and reduce manual oversight for standard queries.

### SLA Tracking (Completed)
- [x] **SLA Calculation:** `SLA.gs` calculates SLA targets by tier (Free: 72h, Individual: 48h, Pro: 24h, Enterprise: 4h)
- [x] **Urgent Priority Handling:** SLA halved for urgent tickets
- [x] **New Sheet Columns:** Added columns N-V to Tickets sheet (ProcessFromSheet layout):
    - N: Confidence Score
    - O: Auto-Send Eligible
    - P: Scheduled Send Time
    - Q: Auto-Send Status
    - R: Cancellation Reason
    - S: SLA Target (hrs)
    - T: SLA Breach Time
    - U: SLA Status (OK/At Risk/Breached)
    - V: Time to SLA (hrs)
- [x] **Hourly SLA Check:** Trigger runs `checkSLABreachesFromSheet()` every hour
- [x] **Google Chat Alerts:** Notifications for at-risk and breached tickets

### Auto-Send (Completed)
- [x] **Confidence Scoring:** Claude prompt includes confidence scoring guidelines (0.0-1.0)
- [x] **Eligibility Check:** `isAutoSendEligible()` validates:
    - Confidence ≥ 95%
    - Category in allowed list (technical, billing, account, feature-request)
    - Not security/bug-report category
    - Not urgent priority
    - No escalation required
    - No security issues detected
    - Not Enterprise tier
- [x] **10-Minute Delay:** Scheduled sends allow cancellation window
- [x] **Auto-Send Execution:** `executeScheduledSendFromSheet()` runs every minute
- [x] **Cancellation Support:** `cancelScheduledSendFromSheet()` allows manual intervention
- [x] **Gmail Labels:** Support/AutoSend/Pending, Sent, Cancelled
- [x] **Retry Logic:** Failed sends retry once after 5 minutes

---

## Phase 5: Canned Response Templates (COMPLETED)

**Goal:** Improve consistency and speed of responses with reusable templates.

- [x] **Templates Sheet:** New "Templates" sheet with columns:
    - Template ID, Name, Category, Keywords, Response Template, Variables, Priority, Active, Last Used, Use Count, Created At, Created By
- [x] **Template Matching:** `findMatchingTemplate()` scores templates by category + keyword matches
- [x] **Variable Substitution:** Supports `{{customer_name}}`, `{{tier}}`, `{{docs_url}}`, `{{app_url}}`, `{{account_count}}`, `{{coverage_score}}`
- [x] **Usage Tracking:** Automatic Last Used and Use Count updates
- [x] **Sample Templates:** Pre-populated with common responses (upgrade, AWS connection, feature requests, coverage explanation, account limits)

---

## Phase 6: Customer CRM Integration (COMPLETED)

**Goal:** Comprehensive customer tracking for proactive support, renewal management, and churn prevention.

### Backend Endpoint (Completed)
- [x] **`/api/support/customers` endpoint:** Returns all customers with CRM data
- [x] **Upgrade Opportunity Detection:** Identifies customers near limits or highly engaged
- [x] **Churn Risk Scoring:** Detects payment issues, inactivity, scheduled cancellations
- [x] **Renewal Status Tracking:** Monitors upcoming renewals (7, 3, 1 day warnings)
- [x] **Environment-Aware Response:** Returns staging/production for correct URLs

### Apps Script Integration (Completed)
- [x] **`CustomerCRM.gs`:** New file for CRM sync and notifications
- [x] **`syncCustomers()` function:** Daily sync from backend to Customers sheet
- [x] **Conditional Formatting:** Visual alerts for churn risk, renewals, attention needed
- [x] **Google Chat Alerts:** Automated notifications for high-risk customers and renewals
- [x] **CRM Summary Sheet:** Aggregated metrics (MRR, tier breakdown, at-risk counts)

### Environment Configuration (Completed)
- [x] **`CONFIG.APP_URL`:** Environment-aware frontend URL (staging.a13e.com / app.a13e.com)
- [x] **`CONFIG.DOCS_URL`:** Environment-aware documentation URL
- [x] **`CONFIG.ENVIRONMENT`:** Centralised environment detection

### Customers Sheet Columns (A-X)
| Column | Field | Description |
|--------|-------|-------------|
| A | Email | Customer email (primary key) |
| B | Full Name | Customer name |
| C | Organisation | Organisation name |
| D | Registered | Registration date |
| E | Days Active | Days since registration |
| F | Tier | Subscription tier (colour-coded) |
| G | Status | Subscription status |
| H | Monthly £ | Monthly value (GBP) |
| I | Renewal Date | Next billing date |
| J | Days to Renewal | Days until renewal (colour-coded) |
| K | Accounts | "X / Y" cloud accounts |
| L | Team | "X / Y" team members |
| M | Last Login | Last login timestamp |
| N | Days Inactive | Days since login (colour-coded) |
| O | Last Scan | Last scan timestamp |
| P | Scans (30d) | Scans in last 30 days |
| Q | Coverage % | Average coverage score |
| R | Upgrade Opp | Upgrade opportunity flag |
| S | Upgrade Reason | Why upgrade opportunity |
| T | Churn Risk | none/low/medium/high (colour-coded) |
| U | Churn Reasons | Comma-separated reasons |
| V | Attention | Needs attention flag |
| W | Attention Reasons | Why attention needed |
| X | Last Synced | Last sync timestamp |

### Setup
1. Run `setupCustomerSyncTrigger()` to configure daily sync at 7 AM
2. Run `syncCustomersNow()` for immediate sync
3. Run `testCRMEndpoint()` to verify API connectivity

---

## Phase 7: Analytics & Reporting (Planned)

**Goal:** Better visibility into support performance and customer issues.

- [ ] **Looker Studio Dashboard:** Connect Google Sheets to Looker Studio for visualisation
- [ ] **Common Issues Report:** Weekly summary of top ticket categories
- [ ] **Resolution Time Tracking:** Automatic calculation when tickets marked resolved
- [ ] **Customer Satisfaction Survey:** Optional follow-up email after resolution
- [ ] **AI Accuracy Metrics:** Track how often AI drafts are used vs modified vs auto-sent

---

## Phase 8: Advanced Features (Future)

**Goal:** Scale support operations as customer base grows.

- [ ] **Live Chat Integration:** Consider Tawk.to or similar free option
- [ ] **Customer Self-Service Portal:** Build in-app support ticket history
- [ ] **Multi-Operator Support:** Team assignment and handoff
- [ ] **Customer Portal:** Let customers view their ticket history in-app

---

## Technical Debt

- [ ] **Test Coverage:** Add unit tests for Apps Script functions
- [ ] **Error Monitoring:** Centralised error logging and alerting
- [ ] **Documentation:** API documentation for customer context endpoint
- [ ] **Backup:** Automated backup of CRM spreadsheet data

---

## Migration Triggers

Consider migrating to a dedicated helpdesk (Freshdesk, HelpScout) when:

- Volume exceeds 500 tickets/month
- Hiring additional support staff
- Enterprise customers require formal SLA guarantees
- Customer portal becomes essential
- Reporting requirements exceed Sheets capabilities

---

## ProcessFromSheet Integration

**Status: COMPLETED (January 2026)**

The support system processes tickets from the CRM sheet (backend submission) rather than monitoring email directly.

### Column Layout (A-V)
| Column | Field |
|--------|-------|
| A-M | Original columns (Ticket ID → AI Draft) |
| N | Confidence Score |
| O | Auto-Send Eligible |
| P | Scheduled Send Time |
| Q | Auto-Send Status |
| R | Cancellation Reason |
| S | SLA Target (hrs) |
| T | SLA Breach Time |
| U | SLA Status |
| V | Time to SLA (hrs) |

### Key Functions
- `processNewTicketsFromSheet()` - Main processing (every 5 min)
- `executeScheduledSendFromSheet()` - Auto-send execution (every 1 min)
- `checkSLABreachesFromSheet()` - SLA monitoring (hourly)
- `addNewColumnsToTicketsSheet()` - One-time column setup
- `testFullIntegration()` - Comprehensive test suite

### Integrated Features
1. **Knowledge Base Search** - Searches Drive for relevant docs before AI call
2. **Template Matching** - Finds matching canned response templates
3. **Enhanced AI Prompt** - Includes KB context and template guidance
4. **Auto-Send Scheduling** - 10-minute delay with cancellation support
5. **SLA Tracking** - Automatic calculation and breach monitoring

### Setup Checklist
1. Run `addNewColumnsToTicketsSheet()` to add columns N-V
2. Run `setupTemplatesSheet()` to create Templates sheet
3. Run `setupKBFolderStructure()` and set `KB_FOLDER_ID` in Script Properties
4. Run `setupSheetTriggers()` to configure all triggers
5. Upload documentation files to Knowledge Base folder

---

## Changelog

| Date | Changes |
|------|---------|
| Jan 2026 | Phase 6 completed: Customer CRM integration with churn detection, upgrade opportunities, renewal tracking |
| Jan 2026 | ProcessFromSheet integration: All features (KB, templates, auto-send, SLA) integrated into sheet-based flow |
| Jan 2026 | Phase 3-5 completed: Knowledge Base integration, SLA management, auto-send with confidence scoring, canned response templates |
| Jan 2026 | Phase 2 completed: environment-aware URLs, accurate gap counts, production hardening |
| Dec 2025 | Phase 1 completed: core infrastructure, Claude integration, backend API |
