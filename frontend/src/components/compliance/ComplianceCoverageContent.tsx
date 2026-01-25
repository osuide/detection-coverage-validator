/**
 * Compliance Coverage Content Component.
 *
 * Displays compliance framework coverage with framework selector,
 * coverage summary cards, cloud applicability filters, and detailed breakdown.
 */

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ExternalLink,
  Cloud,
  Filter,
  ChevronDown,
  ChevronRight,
  Info,
} from 'lucide-react'
import { complianceApi, CloudApplicability } from '../../services/complianceApi'
import { detectionsApi, Detection, DetectionEffectiveness } from '../../services/api'
import { FrameworkCard } from './FrameworkCard'
import { FamilyCoverageChart } from './FamilyCoverageChart'
import { ControlsTable } from './ControlsTable'
import { CoverageDetailModal } from './CoverageDetailModal'
import { SecurityPostureCard } from '../SecurityPostureCard'

type ModalType = 'covered' | 'partial' | 'uncovered' | 'total' | 'cloud_detectable' | 'customer' | 'provider' | 'not_assessable' | null

interface InitialModalState {
  modalType: ModalType
  frameworkId: string | null
  controlId: string | null
}

interface ComplianceCoverageContentProps {
  accountId: string
  initialModalState?: InitialModalState
  cloudProvider?: 'aws' | 'gcp' | 'azure'  // Filter cloud services by provider
}

// Cloud applicability filter options
const applicabilityFilters: { value: CloudApplicability | 'all'; label: string }[] = [
  { value: 'all', label: 'All Controls' },
  { value: 'highly_relevant', label: 'Cloud-Centric' },
  { value: 'moderately_relevant', label: 'Partially Cloud' },
  { value: 'informational', label: 'Informational' },
  { value: 'provider_responsibility', label: 'Provider Managed' },
]

export function ComplianceCoverageContent({ accountId, initialModalState, cloudProvider }: ComplianceCoverageContentProps) {
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedFramework, setSelectedFramework] = useState<string>(
    initialModalState?.frameworkId || ''
  )
  const [cloudFilter, setCloudFilter] = useState<CloudApplicability | 'all'>('all')
  const [familyCoverageExpanded, setFamilyCoverageExpanded] = useState(false)

  // Sync modal state with URL params for back navigation support
  const activeModal = (searchParams.get('modal') as ModalType) || null
  const initialExpandedControl = searchParams.get('control')

  const setActiveModal = (modal: ModalType) => {
    if (modal) {
      setSearchParams({
        modal,
        framework: selectedFramework,
      })
    } else {
      // Clear modal params but keep other params
      const newParams = new URLSearchParams(searchParams)
      newParams.delete('modal')
      newParams.delete('control')
      setSearchParams(newParams)
    }
  }

  // Handle control expansion - update URL so back navigation works
  const handleControlExpand = (controlId: string | null) => {
    const newParams = new URLSearchParams(searchParams)
    if (controlId) {
      newParams.set('control', controlId)
    } else {
      newParams.delete('control')
    }
    setSearchParams(newParams, { replace: true })
  }

  // Initialize modal from URL params on mount
  useEffect(() => {
    if (initialModalState?.modalType && initialModalState?.frameworkId) {
      setSelectedFramework(initialModalState.frameworkId)
    }
  }, [initialModalState])

  // Get compliance summary for all frameworks
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['compliance-summary', accountId],
    queryFn: () => complianceApi.getSummary(accountId),
    enabled: !!accountId,
  })

  // Fetch Security Hub detections for Security Posture section
  const { data: allDetections } = useQuery({
    queryKey: ['securityHubDetections', accountId],
    queryFn: () => detectionsApi.list({
      cloud_account_id: accountId,
      limit: 500,
    }),
    enabled: !!accountId,
  })

  // Extract Security Hub standards with detection effectiveness data
  const securityPostureData = (allDetections?.items ?? [])
    .filter((d: Detection) => {
      if (d.detection_type !== 'security_hub') return false
      const rawConfig = d.raw_config as Record<string, unknown> | undefined
      return rawConfig?.standard_id && rawConfig?.detection_effectiveness
    })
    .map((d: Detection) => {
      const rawConfig = d.raw_config as Record<string, unknown>
      return {
        standardId: rawConfig.standard_id as string,
        standardName: rawConfig.standard_name as string,
        effectiveness: rawConfig.detection_effectiveness as DetectionEffectiveness,
        region: d.region,
        // Detection coverage info (controls enabled)
        enabledControls: rawConfig.enabled_controls_count as number,
        totalControls: rawConfig.total_controls_count as number,
      }
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

  // Filter gaps by cloud applicability
  const filteredGaps =
    cloudFilter === 'all'
      ? coverage?.top_gaps ?? []
      : (coverage?.top_gaps ?? []).filter(
          (gap) => gap.cloud_applicability === cloudFilter
        )

  return (
    <div className="space-y-6">
      {/* Security Hub Posture - Side-by-side Detection Coverage & Effectiveness */}
      {securityPostureData.length > 0 && (
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-lg font-medium text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                Security Hub Posture
              </h3>
              <p className="text-sm text-gray-400 mt-1">
                Detection effectiveness from Security Hub standards
              </p>
            </div>
          </div>

          {/* Security Hub standard cards - full width, focused on compliance results */}
          <div className="space-y-4">
            {securityPostureData.map((data) => (
              <SecurityPostureCard
                key={data.standardId}
                standardId={data.standardId}
                standardName={data.standardName}
                effectiveness={data.effectiveness}
                region={data.region}
                showFailingControls={true}
                pageSize={5}
                enabledControls={data.enabledControls}
                totalControls={data.totalControls}
              />
            ))}
          </div>
        </div>
      )}

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

            {/* Coverage Stats - Clickable */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <button
                onClick={() => setActiveModal('covered')}
                className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
              >
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-gray-400 group-hover:text-gray-300">Covered</span>
                </div>
                <div className="text-2xl font-bold text-green-400">
                  {coverage.covered_controls}
                </div>
                <div className="text-xs text-gray-500 mt-1 group-hover:text-gray-400">Click for details</div>
              </button>
              <button
                onClick={() => setActiveModal('partial')}
                className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
              >
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400" />
                  <span className="text-sm text-gray-400 group-hover:text-gray-300">Partial</span>
                </div>
                <div className="text-2xl font-bold text-yellow-400">
                  {coverage.partial_controls}
                </div>
                <div className="text-xs text-gray-500 mt-1 group-hover:text-gray-400">Click for details</div>
              </button>
              <button
                onClick={() => setActiveModal('uncovered')}
                className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
              >
                <div className="flex items-center gap-2 mb-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span className="text-sm text-gray-400 group-hover:text-gray-300">Uncovered</span>
                </div>
                <div className="text-2xl font-bold text-red-400">
                  {coverage.uncovered_controls}
                </div>
                <div className="text-xs text-gray-500 mt-1 group-hover:text-gray-400">Click for details</div>
              </button>
              <button
                onClick={() => setActiveModal('total')}
                className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
              >
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-blue-400" />
                  <span className="text-sm text-gray-400 group-hover:text-gray-300">Total</span>
                </div>
                <div className="text-2xl font-bold text-white">
                  {coverage.total_controls}
                </div>
                <div className="text-xs text-gray-500 mt-1 group-hover:text-gray-400">Click for details</div>
              </button>
            </div>

            {/* Cloud Metrics Summary */}
            {coverage.cloud_metrics && (
              <div className="mt-6 pt-4 border-t border-gray-700">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                    <Cloud className="w-4 h-4" />
                    Cloud Detection Analytics
                  </h4>
                  {/* Cloud-Only Filtering Transparency Badge */}
                  {coverage.cloud_metrics.non_cloud_techniques_filtered !== undefined &&
                    coverage.cloud_metrics.non_cloud_techniques_filtered > 0 && (
                    <div
                      className="group relative flex items-center gap-1.5 px-2.5 py-1 bg-slate-700/60 rounded-full text-xs text-slate-400 border border-slate-600/50 hover:bg-slate-700 hover:border-slate-500 transition-all cursor-help"
                    >
                      <Info className="w-3 h-3" />
                      <span>{coverage.cloud_metrics.non_cloud_techniques_filtered} non-cloud filtered</span>
                      {/* Tooltip */}
                      <div className="absolute bottom-full right-0 mb-2 w-72 p-3 bg-gray-900 border border-gray-700 rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
                        <p className="text-xs text-gray-300 leading-relaxed">
                          Coverage calculations focus on techniques detectable via cloud-native logging
                          (CloudTrail, Cloud Audit Logs). Non-cloud techniques like DLL Side-Loading
                          are excluded as they require endpoint detection.
                        </p>
                        <div className="absolute bottom-0 right-4 translate-y-1/2 rotate-45 w-2 h-2 bg-gray-900 border-r border-b border-gray-700" />
                      </div>
                    </div>
                  )}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <button
                    onClick={() => setActiveModal('cloud_detectable')}
                    className="bg-gray-700/30 rounded-lg p-3 text-left hover:bg-gray-700/50 transition-colors cursor-pointer group"
                  >
                    <div className="text-xs text-gray-400 mb-1 group-hover:text-gray-300">Cloud-Detectable</div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-lg font-bold text-green-400">
                        {coverage.cloud_metrics.cloud_coverage_percent.toFixed(0)}%
                      </span>
                      <span className="text-xs text-gray-500">
                        ({coverage.cloud_metrics.cloud_detectable_covered}/
                        {coverage.cloud_metrics.cloud_detectable_total})
                      </span>
                    </div>
                  </button>
                  <button
                    onClick={() => setActiveModal('customer')}
                    className="bg-gray-700/30 rounded-lg p-3 text-left hover:bg-gray-700/50 transition-colors cursor-pointer group"
                  >
                    <div className="text-xs text-gray-400 mb-1 group-hover:text-gray-300">Customer Responsibility</div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-lg font-bold text-blue-400">
                        {coverage.cloud_metrics.customer_responsibility_total}
                      </span>
                      <span className="text-xs text-gray-500">controls</span>
                    </div>
                  </button>
                  <button
                    onClick={() => setActiveModal('provider')}
                    className="bg-gray-700/30 rounded-lg p-3 text-left hover:bg-gray-700/50 transition-colors cursor-pointer group"
                  >
                    <div className="text-xs text-gray-400 mb-1 group-hover:text-gray-300">Provider Managed</div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-lg font-bold text-purple-400">
                        {coverage.cloud_metrics.provider_managed_total}
                      </span>
                      <span className="text-xs text-gray-500">controls</span>
                    </div>
                  </button>
                  <button
                    onClick={() => setActiveModal('not_assessable')}
                    className="bg-gray-700/30 rounded-lg p-3 text-left hover:bg-gray-700/50 transition-colors cursor-pointer group"
                    title="Controls that cannot be assessed via cloud scanning (e.g., training, physical security)"
                  >
                    <div className="text-xs text-gray-400 mb-1 group-hover:text-gray-300">
                      Not Assessable
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-lg font-bold text-gray-500">
                        {coverage.cloud_metrics.not_assessable_total}
                      </span>
                      <span className="text-xs text-gray-500">controls</span>
                    </div>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Family Coverage Chart - Collapsible */}
          {coverage.family_coverage.length > 0 && (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <button
                onClick={() => setFamilyCoverageExpanded(!familyCoverageExpanded)}
                className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-700/50 transition-colors"
              >
                <h3 className="text-lg font-medium text-white flex items-center gap-2">
                  Coverage by Control Family
                  <span className="text-sm font-normal text-gray-400">
                    ({coverage.family_coverage.length} families)
                  </span>
                </h3>
                {familyCoverageExpanded ? (
                  <ChevronDown className="w-5 h-5 text-gray-400" />
                ) : (
                  <ChevronRight className="w-5 h-5 text-gray-400" />
                )}
              </button>
              {familyCoverageExpanded && (
                <div className="px-6 pb-6">
                  <FamilyCoverageChart coverage={coverage.family_coverage} />
                </div>
              )}
            </div>
          )}

          {/* Top Gaps with Cloud Filter */}
          {coverage.top_gaps.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-6">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
                <h3 className="text-lg font-medium text-white">
                  Top Coverage Gaps
                  <span className="text-sm font-normal text-gray-400 ml-2">
                    ({filteredGaps.length} of {coverage.top_gaps.length} controls)
                  </span>
                </h3>

                {/* Cloud Applicability Filter */}
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-gray-400" />
                  <select
                    value={cloudFilter}
                    onChange={(e) =>
                      setCloudFilter(e.target.value as CloudApplicability | 'all')
                    }
                    className="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500"
                  >
                    {applicabilityFilters.map((filter) => (
                      <option key={filter.value} value={filter.value}>
                        {filter.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {filteredGaps.length > 0 ? (
                <ControlsTable controls={filteredGaps} cloudProvider={cloudProvider} />
              ) : (
                <div className="text-center py-8 text-gray-400">
                  <Cloud className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p>No gaps match the selected filter.</p>
                  <button
                    onClick={() => setCloudFilter('all')}
                    className="mt-2 text-blue-400 hover:text-blue-300 text-sm"
                  >
                    Clear filter
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Coverage Detail Modal */}
      {coverage && activeModal && (
        <CoverageDetailModal
          isOpen={!!activeModal}
          onClose={() => setActiveModal(null)}
          title={
            activeModal === 'covered' ? 'Covered Controls' :
            activeModal === 'partial' ? 'Partial Controls' :
            activeModal === 'uncovered' ? 'Uncovered Controls' :
            activeModal === 'total' ? 'All Controls' :
            activeModal === 'cloud_detectable' ? 'Cloud-Detectable Controls' :
            activeModal === 'customer' ? 'Customer Responsibility' :
            activeModal === 'provider' ? 'Provider Managed' :
            'Not Assessable'
          }
          description={
            activeModal === 'covered' ? 'Controls with 80% or more technique coverage. These controls have adequate detection mechanisms in place. Click a control to see which techniques and detections provide coverage.' :
            activeModal === 'partial' ? 'Controls with 40-79% technique coverage. These controls have some detection mechanisms but gaps remain. Click a control to see the technique breakdown.' :
            activeModal === 'uncovered' ? 'Controls with less than 40% technique coverage. These controls need attention to improve detection capabilities. Click a control to see which techniques need detections.' :
            activeModal === 'total' ? 'All controls in this compliance framework with their current coverage status. Click a control to see its technique breakdown.' :
            activeModal === 'cloud_detectable' ? 'Controls that can be assessed via cloud log scanning (AWS CloudTrail, GCP Cloud Logging, etc.). Click a control to see details.' :
            activeModal === 'customer' ? 'Controls that are the customer\'s responsibility to implement and monitor. Click a control to see its technique breakdown.' :
            activeModal === 'provider' ? 'Controls managed by the cloud provider (AWS/GCP). These are typically infrastructure-level controls.' :
            'Controls that cannot be assessed via cloud scanning (e.g., security training, physical security, governance).'
          }
          controls={
            activeModal === 'covered' ? (coverage.controls_by_status?.covered ?? []) :
            activeModal === 'partial' ? (coverage.controls_by_status?.partial ?? []) :
            activeModal === 'uncovered' ? (coverage.controls_by_status?.uncovered ?? []) :
            activeModal === 'total' ? [
              ...(coverage.controls_by_status?.covered ?? []),
              ...(coverage.controls_by_status?.partial ?? []),
              ...(coverage.controls_by_status?.uncovered ?? []),
              ...(coverage.controls_by_status?.not_assessable ?? []),
            ] :
            activeModal === 'cloud_detectable' ? (coverage.controls_by_cloud_category?.cloud_detectable ?? []) :
            activeModal === 'customer' ? (coverage.controls_by_cloud_category?.customer_responsibility ?? []) :
            activeModal === 'provider' ? (coverage.controls_by_cloud_category?.provider_managed ?? []) :
            (coverage.controls_by_cloud_category?.not_assessable ?? [])
          }
          variant={
            activeModal === 'covered' ? 'covered' :
            activeModal === 'partial' ? 'partial' :
            activeModal === 'uncovered' ? 'uncovered' :
            activeModal === 'not_assessable' ? 'not_assessable' :
            'cloud'
          }
          accountId={accountId}
          frameworkId={selectedFramework}
          initialExpandedControl={initialExpandedControl}
          onControlExpand={handleControlExpand}
        />
      )}
    </div>
  )
}
