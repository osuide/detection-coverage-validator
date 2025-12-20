/**
 * Family Coverage Chart Component.
 *
 * Displays a horizontal bar chart showing coverage by control family.
 */

import { FamilyCoverageItem } from '../../services/complianceApi'

interface FamilyCoverageChartProps {
  coverage: FamilyCoverageItem[]
}

export function FamilyCoverageChart({ coverage }: FamilyCoverageChartProps) {
  // Sort by family name for consistent display
  const sortedCoverage = [...coverage].sort((a, b) => a.family.localeCompare(b.family))

  return (
    <div className="space-y-3">
      {sortedCoverage.map((family) => (
        <div key={family.family} className="group">
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm text-gray-300 truncate max-w-[60%]" title={family.family}>
              {family.family}
            </span>
            <div className="flex items-center gap-4 text-xs">
              <span className="text-green-400">{family.covered} covered</span>
              <span className="text-yellow-400">{family.partial} partial</span>
              <span className="text-red-400">{family.uncovered} uncovered</span>
              <span className="text-gray-400 w-12 text-right">{family.percent.toFixed(0)}%</span>
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
          </div>
        </div>
      ))}

      {/* Legend */}
      <div className="flex items-center justify-center gap-6 pt-4 border-t border-gray-700 mt-4">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-green-500 rounded" />
          <span className="text-xs text-gray-400">Covered (80%+ of techniques)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-yellow-500 rounded" />
          <span className="text-xs text-gray-400">Partial (40-80%)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-red-500/50 rounded" />
          <span className="text-xs text-gray-400">Uncovered (&lt;40%)</span>
        </div>
      </div>
    </div>
  )
}
