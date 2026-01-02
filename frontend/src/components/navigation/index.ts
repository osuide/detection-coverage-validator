/**
 * Navigation Components
 *
 * Standardised navigation patterns for the a13e frontend.
 *
 * ## Guidelines
 *
 * ### When to use what:
 *
 * | Page Type | Navigation Pattern |
 * |-----------|-------------------|
 * | Top-level (Dashboard, Coverage) | No back button |
 * | Detail page (TechniqueDetail) | `back` prop with fallback |
 * | Deep hierarchy (Org > Account > Members) | `breadcrumbs` prop |
 * | Settings sub-pages | No back button (sidebar handles) |
 *
 * ### Icon usage:
 * - `ArrowLeft` - Back navigation
 * - `ChevronLeft/Right` - Pagination only
 * - `ChevronRight` - Breadcrumb separators
 *
 * ### Navigation method:
 * - Always use `navigate(-1)` with a fallback route
 * - Fallback ensures deep-linked users can still navigate
 */

export { PageHeader } from './PageHeader'
export type { BreadcrumbItem } from './PageHeader'
