/**
 * Framework Card Component.
 *
 * Displays a compliance framework summary with overall and cloud coverage.
 */

import { Shield, Check, Cloud } from 'lucide-react'
import { ComplianceCoverageSummary } from '../../services/complianceApi'

interface FrameworkCardProps {
  framework: ComplianceCoverageSummary
  selected: boolean
  onSelect: () => void
}

export function FrameworkCard({ framework, selected, onSelect }: FrameworkCardProps) {
  // Determine colour based on coverage
  const getCoverageColour = (percent: number) => {
    if (percent >= 80) return 'text-green-400'
    if (percent >= 50) return 'text-yellow-400'
    return 'text-red-400'
  }

  const getProgressColour = (percent: number) => {
    if (percent >= 80) return 'bg-green-500'
    if (percent >= 50) return 'bg-yellow-500'
    return 'bg-red-500'
  }

  const hasCloudMetrics = framework.cloud_coverage_percent !== null

  return (
    <button
      onClick={onSelect}
      className={`w-full text-left p-4 rounded-lg border transition-all ${
        selected
          ? 'bg-blue-900/30 border-blue-500'
          : 'bg-gray-800 border-gray-700 hover:border-gray-600'
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div
            className={`p-2 rounded-lg ${
              selected ? 'bg-blue-600' : 'bg-gray-700'
            }`}
          >
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="font-medium text-white">{framework.framework_name}</h3>
            <p className="text-sm text-gray-400">
              {framework.covered_controls} of {framework.total_controls} controls covered
            </p>
          </div>
        </div>
        {selected && (
          <Check className="w-5 h-5 text-blue-400" />
        )}
      </div>

      {/* Coverage Progress Bars */}
      <div className="mt-4 space-y-3">
        {/* Overall Coverage */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm text-gray-400">Overall Coverage</span>
            <span className={`text-sm font-medium ${getCoverageColour(framework.coverage_percent)}`}>
              {framework.coverage_percent.toFixed(1)}%
            </span>
          </div>
          <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
            <div
              className={`h-full ${getProgressColour(framework.coverage_percent)} transition-all`}
              style={{ width: `${Math.min(100, framework.coverage_percent)}%` }}
            />
          </div>
        </div>

        {/* Cloud Detection Coverage */}
        {hasCloudMetrics && (
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm text-gray-400 flex items-center gap-1">
                <Cloud className="w-3 h-3" />
                Cloud Detection
              </span>
              <span
                className={`text-sm font-medium ${getCoverageColour(framework.cloud_coverage_percent!)}`}
              >
                {framework.cloud_coverage_percent!.toFixed(1)}%
              </span>
            </div>
            <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full ${getProgressColour(framework.cloud_coverage_percent!)} transition-all`}
                style={{ width: `${Math.min(100, framework.cloud_coverage_percent!)}%` }}
              />
            </div>
          </div>
        )}
      </div>
    </button>
  )
}
