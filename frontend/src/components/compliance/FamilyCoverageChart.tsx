/**
 * Family Coverage Chart Component.
 *
 * Displays a horizontal bar chart showing coverage by control family
 * with shared responsibility model indicators.
 */

import { Cloud, Building, Users } from 'lucide-react'
import { FamilyCoverageItem } from '../../services/complianceApi'

interface FamilyCoverageChartProps {
  coverage: FamilyCoverageItem[]
}

// Shared responsibility icons and labels
const responsibilityConfig: Record<
  string,
  { icon: React.ReactNode; label: string; colour: string }
> = {
  customer: {
    icon: <Users className="w-3 h-3" />,
    label: 'Customer',
    colour: 'text-green-400',
  },
  shared: {
    icon: <Cloud className="w-3 h-3" />,
    label: 'Shared',
    colour: 'text-yellow-400',
  },
  provider: {
    icon: <Building className="w-3 h-3" />,
    label: 'Provider',
    colour: 'text-purple-400',
  },
}

// Cloud applicability styling (including "mixed" for families with multiple types)
const applicabilityStyles: Record<string, string> = {
  highly_relevant: 'border-l-4 border-l-green-500',
  moderately_relevant: 'border-l-4 border-l-yellow-500',
  informational: 'border-l-4 border-l-blue-500',
  provider_responsibility: 'border-l-4 border-l-purple-500',
  mixed: 'border-l-4 border-l-gradient-to-b from-green-500 via-yellow-500 to-blue-500',
}

export function FamilyCoverageChart({ coverage }: FamilyCoverageChartProps) {
  // Sort by family name for consistent display
  const sortedCoverage = [...coverage].sort((a, b) => a.family.localeCompare(b.family))

  // Helper to build tooltip for mixed families
  const buildApplicabilityTooltip = (family: FamilyCoverageItem): string => {
    if (family.cloud_applicability === 'mixed' && family.applicability_breakdown) {
      const parts = Object.entries(family.applicability_breakdown)
        .map(([type, count]) => `${count} ${type.replace('_', ' ')}`)
        .join(', ')
      return `Mixed applicability: ${parts}`
    }
    return family.cloud_applicability
      ? `Cloud applicability: ${family.cloud_applicability.replace('_', ' ')}`
      : ''
  }

  return (
    <div className="space-y-3">
      {sortedCoverage.map((family) => {
        const borderStyle = family.cloud_applicability
          ? applicabilityStyles[family.cloud_applicability] || 'border-l-4 border-l-gray-500'
          : ''
        const responsibility = family.shared_responsibility && family.shared_responsibility !== 'mixed'
          ? responsibilityConfig[family.shared_responsibility]
          : null

        // Calculate assessable count for display
        const assessableCount = family.assessable || (family.total - family.not_assessable)

        return (
          <div
            key={family.family}
            className={`group pl-3 ${borderStyle}`}
            title={buildApplicabilityTooltip(family)}
          >
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 max-w-[50%]">
                <span className="text-sm text-gray-300 truncate" title={family.family}>
                  {family.family}
                </span>
                {responsibility && (
                  <span
                    className={`inline-flex items-center gap-1 text-xs ${responsibility.colour}`}
                    title={`${responsibility.label} responsibility`}
                  >
                    {responsibility.icon}
                  </span>
                )}
                {family.cloud_applicability === 'mixed' && (
                  <span
                    className="inline-flex items-center text-xs text-gray-400 bg-gray-700 px-1.5 py-0.5 rounded"
                    title={buildApplicabilityTooltip(family)}
                  >
                    Mixed
                  </span>
                )}
              </div>
              <div className="flex items-center gap-4 text-xs">
                <span className="text-green-400">{family.covered} covered</span>
                <span className="text-yellow-400">{family.partial} partial</span>
                <span className="text-red-400">{family.uncovered} uncovered</span>
                {family.not_assessable > 0 && (
                  <span className="text-gray-500" title="Cannot be assessed via cloud scanning (administrative/process controls)">
                    {family.not_assessable} N/A
                  </span>
                )}
                <span
                  className="text-gray-400 w-16 text-right"
                  title={`${family.percent.toFixed(0)}% of ${assessableCount} assessable controls are covered`}
                >
                  {family.percent.toFixed(0)}%
                  {family.not_assessable > 0 && (
                    <span className="text-gray-600 text-[10px]"> ({assessableCount})</span>
                  )}
                </span>
              </div>
            </div>

            {/* Stacked Progress Bar */}
            <div className="h-3 bg-gray-700 rounded-full overflow-hidden flex">
              {/* Covered (green) */}
              {family.covered > 0 && (
                <div
                  className="bg-green-500 h-full transition-all"
                  style={{ width: `${(family.covered / family.total) * 100}%` }}
                  title={`${family.covered} covered`}
                />
              )}
              {/* Partial (yellow) */}
              {family.partial > 0 && (
                <div
                  className="bg-yellow-500 h-full transition-all"
                  style={{ width: `${(family.partial / family.total) * 100}%` }}
                  title={`${family.partial} partial`}
                />
              )}
              {/* Uncovered (red) */}
              {family.uncovered > 0 && (
                <div
                  className="bg-red-500/50 h-full transition-all"
                  style={{ width: `${(family.uncovered / family.total) * 100}%` }}
                  title={`${family.uncovered} uncovered`}
                />
              )}
              {/* Not Assessable (gray with pattern) */}
              {family.not_assessable > 0 && (
                <div
                  className="bg-gray-600 h-full transition-all"
                  style={{
                    width: `${(family.not_assessable / family.total) * 100}%`,
                    backgroundImage: 'repeating-linear-gradient(45deg, transparent, transparent 2px, rgba(0,0,0,0.3) 2px, rgba(0,0,0,0.3) 4px)',
                  }}
                  title={`${family.not_assessable} not assessable via cloud scanning`}
                />
              )}
            </div>
          </div>
        )
      })}

      {/* Coverage Legend */}
      <div className="flex flex-wrap items-center justify-center gap-4 pt-4 border-t border-gray-700 mt-4">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-green-500 rounded" />
          <span className="text-xs text-gray-400">Covered (80%+)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-yellow-500 rounded" />
          <span className="text-xs text-gray-400">Partial (40-80%)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-red-500/50 rounded" />
          <span className="text-xs text-gray-400">Uncovered (&lt;40%)</span>
        </div>
        <div className="flex items-center gap-2">
          <div
            className="w-3 h-3 bg-gray-600 rounded"
            style={{ backgroundImage: 'repeating-linear-gradient(45deg, transparent, transparent 1px, rgba(0,0,0,0.4) 1px, rgba(0,0,0,0.4) 2px)' }}
          />
          <span className="text-xs text-gray-400">Not Assessable</span>
        </div>
      </div>

      {/* Cloud Applicability Legend */}
      <div className="flex flex-wrap items-center justify-center gap-4 pt-3 border-t border-gray-700/50 mt-3">
        <span className="text-xs text-gray-500 font-medium">Cloud Relevance:</span>
        <div className="flex items-center gap-1">
          <div className="w-1 h-3 bg-green-500 rounded" />
          <span className="text-xs text-gray-400">Highly Relevant</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-1 h-3 bg-yellow-500 rounded" />
          <span className="text-xs text-gray-400">Moderate</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-1 h-3 bg-blue-500 rounded" />
          <span className="text-xs text-gray-400">Informational</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-1 h-3 bg-purple-500 rounded" />
          <span className="text-xs text-gray-400">Provider Managed</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-1 h-3 bg-gray-500 rounded" />
          <span className="text-xs text-gray-400">Mixed</span>
        </div>
      </div>

      {/* Explanatory note */}
      <div className="text-center pt-2">
        <p className="text-xs text-gray-500 italic">
          Percentages show coverage of assessable controls only. N/A controls require manual review.
        </p>
      </div>

      {/* Shared Responsibility Legend */}
      <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
        <span className="text-xs text-gray-500 font-medium">Responsibility:</span>
        <div className="flex items-center gap-1 text-green-400">
          <Users className="w-3 h-3" />
          <span className="text-xs">Customer</span>
        </div>
        <div className="flex items-center gap-1 text-yellow-400">
          <Cloud className="w-3 h-3" />
          <span className="text-xs">Shared</span>
        </div>
        <div className="flex items-center gap-1 text-purple-400">
          <Building className="w-3 h-3" />
          <span className="text-xs">Provider</span>
        </div>
      </div>
    </div>
  )
}
