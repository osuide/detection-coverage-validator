# Support System Backlog

This document tracks future enhancements and features for the A13E Support System.

## Phase 3: Knowledge Base Integration (Planned)
**Goal:** Enable the AI agent to provide more detailed, technically accurate answers by searching a repository of documentation rather than relying solely on its training data.

- [ ] **Create Document Repository:** Set up a dedicated folder in Google Drive (e.g., `A13E Operations/Knowledge Base`) for PDF/Docx files.
- [ ] **Implement Search Logic:** Update `Code.gs` to:
    1.  Receive a user query.
    2.  Search the Drive folder for relevant files.
    3.  Extract text content from the top matching files.
    4.  Feed this "context" into the Claude prompt (RAG pattern).
- [ ] **Update Prompt Engineering:** Modify the system prompt to explicitly use the provided context and cite sources if possible.

## Phase 4: SLA Management & Automation (Planned)
**Goal:** Ensure timely responses and reduce manual oversight for standard queries.

- [ ] **SLA Tracking:**
    -   Add logic to `Code.gs` to calculate "Time Remaining" based on ticket priority (e.g., Critical = 1h, Normal = 24h).
    -   Update the Google Sheet with a "Breach Time" column.
- [ ] **Automated Alerts:**
    -   Create a scheduled trigger (every hour) to check for tickets approaching their SLA breach time.
    -   Send a ping to Google Chat for "At Risk" tickets.
- [ ] **Auto-Send Low Risk Replies:**
    -   Define a "Confidence Threshold" (e.g., > 95%).
    -   For "General" or "Billing" categories with high confidence, skip the draft phase and send the email immediately.
    -   Add a delay (e.g., 5 mins) to allow for manual cancellation if needed.
