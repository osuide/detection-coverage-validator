/**
 * PageHeader Component
 *
 * Standardised page header with optional back navigation, breadcrumbs,
 * title, description, and action buttons.
 *
 * Usage patterns:
 * - Top-level pages (Dashboard, Coverage): No back button, just title
 * - Detail pages (TechniqueDetail): Back button with fallback route
 * - Nested pages (OrgMembers): Breadcrumbs for deep hierarchy
 */

import { ReactNode } from 'react'
import { Link, useNavigate } from 'react-router'
import { ArrowLeft, ChevronRight } from 'lucide-react'

export interface BreadcrumbItem {
  label: string
  href?: string
}

interface PageHeaderProps {
  /** Page title - optional for back-only headers */
  title?: string
  /** Optional description shown below title */
  description?: string | ReactNode
  /** Back navigation configuration */
  back?: {
    /** Label for the back button (e.g., "Coverage", "Organisations") */
    label: string
    /** Fallback route if no browser history */
    fallback: string
  }
  /** Breadcrumb items for deep hierarchies (alternative to back button) */
  breadcrumbs?: BreadcrumbItem[]
  /** Action buttons (right side of header) */
  actions?: ReactNode
  /** Additional content below the title row */
  children?: ReactNode
}

/**
 * Standardised page header component.
 *
 * @example Top-level page (no back button)
 * ```tsx
 * <PageHeader
 *   title="Dashboard"
 *   description="Overview of your cloud security posture"
 * />
 * ```
 *
 * @example Detail page (with back button)
 * ```tsx
 * <PageHeader
 *   title="T1078.004 - Cloud Accounts"
 *   description="Remediation guidance for this technique"
 *   back={{ label: "Coverage", fallback: "/coverage" }}
 * />
 * ```
 *
 * @example Nested page (with breadcrumbs)
 * ```tsx
 * <PageHeader
 *   title="Member Accounts"
 *   breadcrumbs={[
 *     { label: "Organisations", href: "/organizations" },
 *     { label: "AWS Production", href: "/organizations/123" },
 *     { label: "Members" }
 *   ]}
 * />
 * ```
 */
export function PageHeader({
  title,
  description,
  back,
  breadcrumbs,
  actions,
  children,
}: PageHeaderProps) {
  const navigate = useNavigate()

  const handleBack = () => {
    // Use browser history if available, otherwise fallback
    if (window.history.length > 2) {
      navigate(-1)
    } else {
      navigate(back!.fallback)
    }
  }

  return (
    <div className="mb-8">
      {/* Back button */}
      {back && !breadcrumbs && (
        <button
          onClick={handleBack}
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-white transition-colors mb-4 group"
        >
          <ArrowLeft className="h-4 w-4 group-hover:-translate-x-0.5 transition-transform" />
          <span>Back to {back.label}</span>
        </button>
      )}

      {/* Breadcrumbs (alternative to back button for deep hierarchies) */}
      {breadcrumbs && breadcrumbs.length > 0 && (
        <nav className="flex items-center gap-1.5 text-sm text-gray-400 mb-4">
          {breadcrumbs.map((item, index) => (
            <span key={index} className="flex items-center gap-1.5">
              {index > 0 && <ChevronRight className="h-3.5 w-3.5 text-gray-600" />}
              {item.href ? (
                <Link
                  to={item.href}
                  className="hover:text-white transition-colors"
                >
                  {item.label}
                </Link>
              ) : (
                <span className="text-gray-300">{item.label}</span>
              )}
            </span>
          ))}
        </nav>
      )}

      {/* Title row - only render if title or actions provided */}
      {(title || actions) && (
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            {title && <h1 className="text-2xl font-bold text-white">{title}</h1>}
            {description && (
              <div className="mt-1 text-gray-400">
                {typeof description === 'string' ? <p>{description}</p> : description}
              </div>
            )}
          </div>

          {/* Actions */}
          {actions && (
            <div className="flex items-center gap-2 ml-4 shrink-0">
              {actions}
            </div>
          )}
        </div>
      )}

      {/* Additional content */}
      {children}
    </div>
  )
}

export default PageHeader
