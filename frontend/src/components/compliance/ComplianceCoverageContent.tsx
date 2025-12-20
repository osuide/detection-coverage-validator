/**
 * Compliance Coverage Content Component.
 *
 * Displays compliance framework coverage with framework selector,
 * coverage summary cards, and detailed breakdown.
 */

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Shield, AlertTriangle, CheckCircle, XCircle, ExternalLink } from 'lucide-react'
import { complianceApi } from '../../services/complianceApi'
import { FrameworkCard } from './FrameworkCard'
import { FamilyCoverageChart } from './FamilyCoverageChart'
import { ControlsTable } from './ControlsTable'

interface ComplianceCoverageContentProps {
  accountId: string
}

export function ComplianceCoverageContent({ accountId }: ComplianceCoverageContentProps) {
  const [selectedFramework, setSelectedFramework] = useState<string>('')

  // Get compliance summary for all frameworks
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['compliance-summary', accountId],
    queryFn: () => complianceApi.getSummary(accountId),
    enabled: !!accountId,
  })

  // Get detailed coverage for selected framework
  const { data: coverage, isLoading: coverageLoading } = useQuery({
    queryKey: ['compliance-coverage', accountId, selectedFramework],
    queryFn: () => complianceApi.getCoverage(accountId, selectedFramework),
    enabled: !!accountId && !!selectedFramework,
  })

  // Select first framework by default when summary loads
  if (summary && summary.length > 0 && !selectedFramework) {
    setSelectedFramework(summary[0].framework_id)
  }

  if (summaryLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
        <span className="ml-3 text-gray-400">Loading compliance data...</span>
      </div>
    )
  }

  if (!summary || summary.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg p-8 text-center">
        <Shield className="w-12 h-12 text-gray-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">No Compliance Data</h3>
        <p className="text-gray-400 mb-4">
          Compliance coverage data is not yet available for this account.
          Run a scan to calculate compliance coverage.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Framework Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {summary.map((fw) => (
          <FrameworkCard
            key={fw.framework_id}
            framework={fw}
            selected={selectedFramework === fw.framework_id}
            onSelect={() => setSelectedFramework(fw.framework_id)}
          />
        ))}
      </div>

      {/* Detailed Coverage */}
      {coverageLoading && (
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500" />
          <span className="ml-3 text-gray-400">Loading framework details...</span>
        </div>
      )}

      {coverage && (
        <div className="space-y-6">
          {/* Coverage Summary */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-medium text-white">{coverage.framework.name}</h3>
                <p className="text-sm text-gray-400">Version {coverage.framework.version}</p>
              </div>
              {coverage.framework.source_url && (
                <a
                  href={coverage.framework.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 flex items-center gap-1 text-sm"
                >
                  View Source <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>

            {/* Coverage Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-gray-400">Covered</span>
                </div>
                <div className="text-2xl font-bold text-green-400">
                  {coverage.covered_controls}
                </div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400" />
                  <span className="text-sm text-gray-400">Partial</span>
                </div>
                <div className="text-2xl font-bold text-yellow-400">
                  {coverage.partial_controls}
                </div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span className="text-sm text-gray-400">Uncovered</span>
                </div>
                <div className="text-2xl font-bold text-red-400">
                  {coverage.uncovered_controls}
                </div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-blue-400" />
                  <span className="text-sm text-gray-400">Total</span>
                </div>
                <div className="text-2xl font-bold text-white">
                  {coverage.total_controls}
                </div>
              </div>
            </div>
          </div>

          {/* Family Coverage Chart */}
          {coverage.family_coverage.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-6">
              <h3 className="text-lg font-medium text-white mb-4">Coverage by Control Family</h3>
              <FamilyCoverageChart coverage={coverage.family_coverage} />
            </div>
          )}

          {/* Top Gaps */}
          {coverage.top_gaps.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-6">
              <h3 className="text-lg font-medium text-white mb-4">
                Top Coverage Gaps
                <span className="text-sm font-normal text-gray-400 ml-2">
                  ({coverage.top_gaps.length} controls need attention)
                </span>
              </h3>
              <ControlsTable controls={coverage.top_gaps} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}
