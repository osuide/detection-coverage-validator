# Documentation Site Implementation Plan

**Created:** 2025-12-19
**Status:** PLANNING
**Estimated Effort:** 5-7 hours

---

## Executive Summary

This plan covers:
1. **CloudWatch Parser Fix** - Commit and deploy pending backend changes
2. Fixing content issues in existing markdown docs (pricing, versions)
3. Converting markdown docs to HTML pages in the frontend
4. Adding a `/docs` section accessible from the main site

> **Note:** Microsoft SSO has been removed from documentation (2025-12-20). Only Google and GitHub SSO are supported.

---

## Part 0: CloudWatch Parser Fix (URGENT)

### Issue
The CloudWatch scanner has uncommitted fixes that need to be deployed:
- New `CLOUDWATCH_ALARM` detection type
- DateTime serialization fix for JSON storage
- Migration file `014_add_cloudwatch_alarm_type.py`

### Files Changed (Uncommitted)
- `backend/app/models/detection.py` - Added CLOUDWATCH_ALARM enum
- `backend/app/scanners/aws/cloudwatch_scanner.py` - Fixed datetime serialization
- `backend/alembic/versions/014_add_cloudwatch_alarm_type.py` - New migration

### Steps to Fix
1. [ ] Commit the CloudWatch parser changes
2. [ ] Push to main branch
3. [ ] Build and push new Docker image to ECR
4. [ ] Run migration on staging database
5. [ ] Deploy updated ECS task
6. [ ] Verify scanner works correctly

---

## Part 1: Content Fixes

### 1.1 Pricing Alignment

**Problem:** Documentation shows $199/mo but Stripe has $29/mo

**Files to Update:**
- `docs/user-guide/README.md`
- `docs/user-guide/billing-subscription.md`

**Changes:**

| Item | Current (Wrong) | Correct (Stripe) |
|------|-----------------|------------------|
| Subscriber Plan | $199/mo | $29/mo |
| Enterprise Plan | Custom | $499/mo |
| Additional Account | $50/mo | $9/mo |
| Additional User | $10/mo | Remove (included) |

**Updated Pricing Table:**
```
| Plan | Price | Accounts | Users |
|------|-------|----------|-------|
| Free Scan | $0 | 1 | 1 |
| Subscriber | $29/mo | 3 (+$9/mo each) | 5 |
| Enterprise | $499/mo | Unlimited | Unlimited |
```

### 1.2 Version Number Updates

**Problem:** Docs show "Version 2.5.0" but actual is "0.1.0-alpha"

**Files to Update:**
- `docs/user-guide/README.md` (lines 274, 350-351)

**Change:**
```
Before: Current Version: 2.5.0 (December 2025)
After:  Current Version: 0.1.0 (December 2025)
```

### 1.3 Microsoft SSO Removal ✅ COMPLETED

**Status:** Completed on 2025-12-20

Microsoft SSO references have been removed from all documentation. Only Google and GitHub SSO are supported.

---

## Part 2: Frontend Documentation Site

### 2.1 Architecture Decision

**Approach:** Public `/docs` route accessible from Landing page and authenticated app

**Rationale:**
- Docs should be public (helps with SEO, user education before signup)
- Accessible from both landing page footer AND authenticated sidebar
- Own layout with left sidebar for navigation
- Clean, readable design matching site aesthetic

### 2.2 Technical Implementation

#### Dependencies to Add

```bash
npm install react-markdown remark-gfm rehype-highlight
```

| Package | Purpose |
|---------|---------|
| `react-markdown` | Render markdown as React components |
| `remark-gfm` | GitHub Flavored Markdown (tables, strikethrough) |
| `rehype-highlight` | Syntax highlighting for code blocks |

#### File Structure

```
frontend/src/
├── pages/
│   └── docs/
│       ├── DocsIndex.tsx        # /docs landing page
│       ├── DocsPage.tsx         # Individual doc page
│       └── docs-content.ts      # Static content (HTML strings)
├── components/
│   └── docs/
│       ├── DocsLayout.tsx       # Layout with sidebar
│       ├── DocsSidebar.tsx      # Navigation sidebar
│       ├── DocsContent.tsx      # Content renderer
│       ├── DocsSearch.tsx       # Search functionality
│       └── DocsBreadcrumb.tsx   # Breadcrumb navigation
└── styles/
    └── docs.css                 # Documentation-specific styles
```

#### Routes to Add (App.tsx)

```tsx
// Public documentation routes
<Route path="/docs" element={<DocsIndex />} />
<Route path="/docs/:slug" element={<DocsPage />} />
```

#### Navigation Updates

**Landing.tsx Footer:**
- Add "Documentation" link pointing to `/docs`

**Layout.tsx Sidebar:**
- Add Help/Docs icon linking to `/docs` (opens in new context or same window)

### 2.3 Content Strategy

#### Option A: Static HTML in Code (Recommended for MVP)

Convert markdown to static TypeScript/HTML content:

```typescript
// docs-content.ts
export const docsContent = {
  'getting-started': {
    title: 'Getting Started',
    description: 'New to A13E? Start here.',
    readTime: '10 min',
    content: `<article>...</article>`,
  },
  'connecting-aws': {
    title: 'Connecting AWS Accounts',
    // ...
  },
}
```

**Pros:**
- No build-time markdown processing needed
- Fast loading (no parsing at runtime)
- Easy to deploy
- Works with current build setup

**Cons:**
- Manual conversion needed
- Updates require code changes

#### Option B: Runtime Markdown Rendering (Future Enhancement)

Fetch markdown files and render at runtime:

```typescript
const [content, setContent] = useState('')
useEffect(() => {
  fetch('/docs/getting-started.md')
    .then(r => r.text())
    .then(setContent)
}, [])
```

**Pros:**
- Easy content updates
- Markdown stays as source of truth

**Cons:**
- Requires serving markdown files
- Slightly slower initial load

**Recommendation:** Start with Option A for MVP, migrate to Option B later.

### 2.4 Page Designs

#### Docs Index Page (`/docs`)

```
┌─────────────────────────────────────────────────────────────────┐
│  [A13E Logo]                              [Login] [Get Started] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              A13E Documentation                          │   │
│  │                                                          │   │
│  │  Everything you need to get started with A13E            │   │
│  │  Detection Coverage Validator                            │   │
│  │                                                          │   │
│  │  [Search documentation...]                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ 📚           │  │ 🔗           │  │ 🔍           │         │
│  │ Getting      │  │ Connecting   │  │ Running      │         │
│  │ Started      │  │ AWS Accounts │  │ Scans        │         │
│  │              │  │              │  │              │         │
│  │ 10 min read  │  │ 15 min read  │  │ 12 min read  │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ 📊           │  │ 👥           │  │ 💳           │         │
│  │ Understanding│  │ Team         │  │ Billing &    │         │
│  │ Coverage     │  │ Management   │  │ Subscription │         │
│  │              │  │              │  │              │         │
│  │ 20 min read  │  │ 15 min read  │  │ 12 min read  │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Individual Doc Page (`/docs/getting-started`)

```
┌─────────────────────────────────────────────────────────────────┐
│  [A13E Logo]                              [Login] [Get Started] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────┐  ┌──────────────────────────────────────┐  │
│  │ DOCUMENTATION  │  │  Docs > Getting Started              │  │
│  │                │  │                                      │  │
│  │ Getting Started│  │  # Getting Started                   │  │
│  │ ├─ What is A13E│  │                                      │  │
│  │ ├─ Creating    │  │  Welcome to A13E! This guide will    │  │
│  │ │  Account     │  │  help you get started...             │  │
│  │ ├─ Signing In  │  │                                      │  │
│  │ └─ Dashboard   │  │  ## What is A13E?                    │  │
│  │                │  │                                      │  │
│  │ Connecting AWS │  │  A13E Detection Coverage Validator   │  │
│  │ Running Scans  │  │  helps security teams understand...  │  │
│  │ Understanding  │  │                                      │  │
│  │   Coverage     │  │  ## Creating Your Account            │  │
│  │ Team Mgmt      │  │                                      │  │
│  │ Billing        │  │  ### Option 1: Email/Password        │  │
│  │                │  │                                      │  │
│  │ ─────────────  │  │  1. Navigate to signup page...       │  │
│  │ Need help?     │  │                                      │  │
│  │ support@a13e.com│  │  [Previous: Home]    [Next: AWS →]   │  │
│  └────────────────┘  └──────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.5 Content Guidelines (For Document Reviewer Agent)

The document reviewer agent should ensure:

#### Length Guidelines

| Document | Target Length | Current | Action |
|----------|---------------|---------|--------|
| Getting Started | 800-1000 words | ~1100 | Trim slightly |
| Connecting AWS | 1200-1500 words | ~1900 | Trim 20% |
| Running Scans | 1000-1200 words | ~1500 | Trim slightly |
| Understanding Coverage | 1500-2000 words | ~2200 | OK (complex topic) |
| Team Management | 1000-1200 words | ~2300 | Trim 40% |
| Billing | 1000-1200 words | ~2400 | Trim 50% |

#### Readability Checklist

- [ ] **Headings**: Clear hierarchy (H1 > H2 > H3), scannable
- [ ] **Paragraphs**: Max 3-4 sentences each
- [ ] **Lists**: Use bullets for 3+ related items
- [ ] **Code blocks**: Only when necessary, with context
- [ ] **Tables**: For comparisons, keep under 5 columns
- [ ] **Images**: Add screenshots for complex UI flows (future)
- [ ] **Links**: Internal links use relative paths
- [ ] **Jargon**: Define technical terms on first use
- [ ] **Action-oriented**: Start sections with verbs ("Click", "Navigate", "Enter")

#### Audience Balance

For each section, ensure content works for:

**Technical Users:**
- Include CLI commands, API references
- Provide IAM policy JSON snippets
- Reference AWS service names accurately

**Non-Technical Users:**
- Lead with "what" before "how"
- Use analogies for complex concepts
- Provide step-by-step with screenshots
- Avoid assuming AWS expertise

#### Sections to Simplify

1. **Connecting AWS Accounts** - The 3 methods (CloudFormation, Terraform, Manual) could be collapsed with CloudFormation as default, others in expandable sections

2. **Team Management** - Permissions matrix is very detailed; consider moving to appendix or collapsible section

3. **Understanding Coverage** - MITRE explanation is excellent but long; add TL;DR summary at top

4. **Billing** - FAQ section is extensive; move to separate FAQ page or collapsible

---

## Part 3: Implementation Steps

### Phase 1: Content Fixes (30 min)

1. [ ] Update pricing in `billing-subscription.md`
2. [ ] Update pricing in `README.md`
3. [ ] Update version numbers in `README.md`
4. [x] Remove Microsoft SSO references from all docs ✅
5. [ ] Review and commit changes

### Phase 2: Document Review & Optimization (1-2 hours)

Use document reviewer agent to:

1. [ ] Review `getting-started.md` - trim to ~1000 words
2. [ ] Review `connecting-aws-accounts.md` - trim to ~1500 words
3. [ ] Review `running-scans.md` - trim to ~1200 words
4. [ ] Review `understanding-coverage.md` - add TL;DR, keep detail
5. [ ] Review `team-management.md` - trim to ~1200 words
6. [ ] Review `billing-subscription.md` - trim to ~1200 words
7. [ ] Ensure consistent formatting across all docs

### Phase 3: Frontend Implementation (2-3 hours)

1. [ ] Install dependencies (`react-markdown`, `remark-gfm`)
2. [ ] Create `DocsLayout.tsx` component
3. [ ] Create `DocsSidebar.tsx` component
4. [ ] Create `DocsIndex.tsx` page
5. [ ] Create `DocsPage.tsx` page
6. [ ] Convert markdown content to static HTML/TSX
7. [ ] Add routes to `App.tsx`
8. [ ] Add navigation links (Landing footer, Layout sidebar)
9. [ ] Style documentation pages (Tailwind)
10. [ ] Test all pages render correctly

### Phase 4: Testing & Polish (30 min)

1. [ ] Test all doc pages load
2. [ ] Test navigation between pages
3. [ ] Test mobile responsiveness
4. [ ] Verify code blocks render correctly
5. [ ] Check all internal links work
6. [ ] Review for consistent styling

---

## Part 4: File Changes Summary

### Files to Modify

| File | Changes |
|------|---------|
| `docs/user-guide/README.md` | Fix pricing, version, remove MS SSO |
| `docs/user-guide/billing-subscription.md` | Fix pricing throughout |
| `docs/user-guide/getting-started.md` | Remove MS SSO |
| `docs/user-guide/team-management.md` | Remove MS SSO, trim length |
| `frontend/package.json` | Add markdown dependencies |
| `frontend/src/App.tsx` | Add /docs routes |
| `frontend/src/pages/Landing.tsx` | Add docs link in footer |
| `frontend/src/components/Layout.tsx` | Add docs link in sidebar |

### Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/docs/DocsIndex.tsx` | Docs landing page |
| `frontend/src/pages/docs/DocsPage.tsx` | Individual doc viewer |
| `frontend/src/pages/docs/docs-content.ts` | Static doc content |
| `frontend/src/components/docs/DocsLayout.tsx` | Docs page layout |
| `frontend/src/components/docs/DocsSidebar.tsx` | Navigation sidebar |

---

## Success Criteria

- [ ] All pricing matches Stripe ($29/mo Subscriber, $499/mo Enterprise, $9/mo additional account)
- [ ] Version shows 0.1.0 (not 2.5.0)
- [x] No Microsoft SSO references in any doc ✅
- [ ] `/docs` route loads docs index page
- [ ] All 6 doc pages accessible and readable
- [ ] Sidebar navigation works
- [ ] Mobile responsive
- [ ] Links from Landing and Layout work
- [ ] Content is appropriately concise (per guidelines)

---

## Notes

- Consider adding search functionality in Phase 2 (future enhancement)
- Screenshots/images can be added later
- API documentation is separate scope (OpenAPI/Swagger)
- Consider adding feedback mechanism ("Was this helpful?")

---

**Document Status:** Ready for implementation
**Next Step:** Execute Phase 1 (Content Fixes)
