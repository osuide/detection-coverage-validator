import { useQuery } from '@tanstack/react-query'
import { Shield, Search, Filter, ChevronDown, Eye, Activity, Zap, CheckCircle, Lock, AlertTriangle, XCircle, HelpCircle, Bell, MapPin, Cloud } from 'lucide-react'
import { detectionsApi, Detection, EvaluationSummary } from '../services/api'
import { useState, useMemo } from 'react'
import { useSelectedAccount } from '../hooks/useSelectedAccount'
import DetectionDetailModal from '../components/DetectionDetailModal'
import SecurityHubAggregatedCard, {
  isSecurityHubAggregated,
  SecurityHubAggregatedConfig,
} from '../components/SecurityHubAggregatedCard'
import {
  RegionalAggregatedCard,
  groupDetectionsByName,
} from '../components/InspectorAggregatedCard'

type SortField = 'name' | 'detection_type' | 'region' | 'status' | 'mapping_count' | 'discovered_at'
type SortDirection = 'asc' | 'desc'

/** Get display name for cloud provider */
function getProviderDisplayName(provider?: 'aws' | 'gcp' | 'azure'): string {
  switch (provider) {
    case 'gcp':
      return 'GCP'
    case 'azure':
      return 'Azure'
    case 'aws':
    default:
      return 'AWS'
  }
}

const detectionTypeConfig: Record<string, { label: string; icon: React.ElementType; color: string; bgColor: string }> = {
  'cloudwatch_logs_insights': {
    label: 'CloudWatch Logs',
    icon: Activity,
    color: 'text-orange-400',
    bgColor: 'bg-orange-900/30'
  },
  'cloudwatch_alarm': {
    label: 'CloudWatch Alarms',
    icon: Bell,
    color: 'text-amber-400',
    bgColor: 'bg-amber-900/30'
  },
  'eventbridge_rule': {
    label: 'EventBridge',
    icon: Zap,
    color: 'text-purple-400',
    bgColor: 'bg-purple-900/30'
  },
  'guardduty_finding': {
    label: 'GuardDuty',
    icon: Shield,
    color: 'text-red-400',
    bgColor: 'bg-red-900/30'
  },
  'config_rule': {
    label: 'Config Rule',
    icon: CheckCircle,
    color: 'text-green-400',
    bgColor: 'bg-green-900/30'
  },
  'security_hub': {
    label: 'Security Hub',
    icon: Lock,
    color: 'text-blue-400',
    bgColor: 'bg-blue-900/30'
  },
  'inspector_finding': {
    label: 'Inspector',
    icon: Search,
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-900/30'
  },
  'macie_finding': {
    label: 'Macie',
    icon: Eye,
    color: 'text-pink-400',
    bgColor: 'bg-pink-900/30'
  },
  // GCP Detection Types
  'gcp_cloud_logging': {
    label: 'Cloud Logging',
    icon: Activity,
    color: 'text-blue-400',
    bgColor: 'bg-blue-900/30'
  },
  'gcp_security_command_center': {
    label: 'Security Command Center',
    icon: Shield,
    color: 'text-blue-400',
    bgColor: 'bg-blue-900/30'
  },
  'gcp_eventarc': {
    label: 'Eventarc',
    icon: Zap,
    color: 'text-blue-400',
    bgColor: 'bg-blue-900/30'
  },
  // Azure Detection Types
  'azure_defender': {
    label: 'Defender for Cloud',
    icon: Shield,
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-900/30'
  },
  'azure_policy': {
    label: 'Azure Policy',
    icon: CheckCircle,
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-900/30'
  }
}

function DetectionTypeBadge({ type }: { type: string }) {
  const config = detectionTypeConfig[type] || {
    label: type.replace(/_/g, ' '),
    icon: AlertTriangle,
    color: 'text-gray-400',
    bgColor: 'bg-gray-700/30'
  }
  const Icon = config.icon

  return (
    <span className={`inline-flex items-center px-2.5 py-1 text-xs font-medium rounded-full ${config.bgColor} ${config.color}`}>
      <Icon className="h-3 w-3 mr-1" />
      {config.label}
    </span>
  )
}

/**
 * Displays compliance/evaluation status for a detection.
 * - Config Rules: Shows COMPLIANT/NON_COMPLIANT with resource count
 * - CloudWatch Alarms: Shows alarm state (OK/ALARM)
 * - Other types: No indicator shown
 */
function ComplianceIndicator({ evaluation }: { evaluation?: EvaluationSummary }) {
  if (!evaluation) return <span className="text-gray-500 text-sm">-</span>

  // Config rule compliance
  if (evaluation.type === 'config_compliance') {
    const { compliance_type, non_compliant_count } = evaluation

    if (compliance_type === 'COMPLIANT') {
      return (
        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-green-900/30 text-green-400">
          <CheckCircle className="h-3 w-3 mr-1" />
          Compliant
        </span>
      )
    }

    if (compliance_type === 'NON_COMPLIANT') {
      return (
        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-red-900/30 text-red-400">
          <XCircle className="h-3 w-3 mr-1" />
          {non_compliant_count || 0} non-compliant
        </span>
      )
    }

    if (compliance_type === 'NOT_APPLICABLE') {
      return (
        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-gray-700/30 text-gray-400">
          N/A
        </span>
      )
    }

    // INSUFFICIENT_DATA
    return (
      <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-yellow-900/30 text-yellow-400">
        <HelpCircle className="h-3 w-3 mr-1" />
        No data
      </span>
    )
  }

  // Alarm state
  if (evaluation.type === 'alarm_state') {
    const { state } = evaluation

    if (state === 'OK') {
      return (
        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-green-900/30 text-green-400">
          OK
        </span>
      )
    }

    if (state === 'ALARM') {
      return (
        <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-red-900/30 text-red-400">
          <AlertTriangle className="h-3 w-3 mr-1" />
          ALARM
        </span>
      )
    }

    return (
      <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-gray-700/30 text-gray-400">
        {state || 'Unknown'}
      </span>
    )
  }

  // EventBridge state
  if (evaluation.type === 'eventbridge_state') {
    return (
      <span className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded-full ${
        evaluation.state === 'ENABLED'
          ? 'bg-green-900/30 text-green-400'
          : 'bg-gray-700/30 text-gray-400'
      }`}>
        {evaluation.state || 'Unknown'}
      </span>
    )
  }

  return <span className="text-gray-500 text-sm">-</span>
}

/** Badge indicating cloud provider-managed detection (vs user-created) */
function ManagedBadge({ isManaged, provider }: { isManaged: boolean; provider?: 'aws' | 'gcp' | 'azure' }) {
  if (!isManaged) return null

  return (
    <span className="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full bg-sky-900/30 text-sky-400 border border-sky-700/50">
      <Cloud className="h-3 w-3 mr-1" />
      {getProviderDisplayName(provider)} Managed
    </span>
  )
}

/** Mobile card component for detection display */
function DetectionCard({
  detection,
  onClick,
  provider
}: {
  detection: Detection
  onClick: () => void
  provider?: 'aws' | 'gcp' | 'azure'
}) {
  return (
    <div
      onClick={onClick}
      className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 cursor-pointer transition-colors"
    >
      <div className="flex items-start justify-between mb-3">
        <h3 className="font-medium text-white line-clamp-2 flex-1 mr-2">{detection.name}</h3>
        <Eye className="h-4 w-4 text-gray-400 shrink-0" />
      </div>
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <DetectionTypeBadge type={detection.detection_type} />
          <span className="text-xs text-gray-400">{detection.region}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
            detection.status === 'active'
              ? 'bg-green-900/30 text-green-400'
              : detection.status === 'disabled'
              ? 'bg-gray-700/30 text-gray-400'
              : 'bg-red-900/30 text-red-400'
          }`}>
            {detection.status}
          </span>
          <span className={`text-sm ${
            detection.mapping_count > 0
              ? 'text-green-400 font-medium'
              : 'text-gray-400'
          }`}>
            {detection.mapping_count} technique{detection.mapping_count !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <ComplianceIndicator evaluation={detection.evaluation_summary} />
          <span className="text-xs text-gray-500">
            {new Date(detection.discovered_at).toLocaleDateString()}
          </span>
        </div>
        {detection.is_managed && (
          <div className="pt-2 border-t border-gray-700 mt-2">
            <ManagedBadge isManaged={detection.is_managed} provider={provider} />
          </div>
        )}
      </div>
    </div>
  )
}

export default function Detections() {
  const { selectedAccount, isLoading: accountsLoading } = useSelectedAccount()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [managedFilter, setManagedFilter] = useState<'all' | 'managed' | 'custom'>('all')
  const [sortField, setSortField] = useState<SortField>('discovered_at')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [selectedDetection, setSelectedDetection] = useState<Detection | null>(null)

  // Fetch detections for the selected account
  const { data, isLoading } = useQuery({
    queryKey: ['detections', selectedAccount?.id],
    queryFn: () => detectionsApi.list({ cloud_account_id: selectedAccount?.id, limit: 500 }),
    enabled: !!selectedAccount,
  })

  const detections = data?.items ?? []

  // Fetch with region coverage enabled for the selected account
  const { data: regionCoverageData } = useQuery({
    queryKey: ['detections-region-coverage', selectedAccount?.id],
    queryFn: () =>
      detectionsApi.list({
        cloud_account_id: selectedAccount?.id,
        limit: 500,
        include_region_coverage: true,
      }),
    enabled: !!selectedAccount,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  })

  // Effective regions from the account (if single account)
  const effectiveRegions = regionCoverageData?.effective_regions

  // Separate aggregated detections from regular ones
  const { securityHubDetections, multiRegionGroups, regularDetections } = useMemo(() => {
    const securityHub: Detection[] = []
    const nonSecurityHub: Detection[] = []

    // First, separate Security Hub aggregated detections
    detections.forEach((d) => {
      if (isSecurityHubAggregated(d)) {
        securityHub.push(d)
      } else {
        nonSecurityHub.push(d)
      }
    })

    // Group remaining detections by name to find multi-region detections
    // Detections with the same name across regions are aggregated
    const { multiRegionGroups: groups, singleRegionDetections } =
      groupDetectionsByName(nonSecurityHub)

    return {
      securityHubDetections: securityHub,
      multiRegionGroups: groups,
      regularDetections: singleRegionDetections,
    }
  }, [detections])

  // Apply filters to regular detections only (aggregated ones shown separately)
  let filteredDetections = regularDetections.filter(d =>
    d.name.toLowerCase().includes(search.toLowerCase())
  )

  if (typeFilter) {
    filteredDetections = filteredDetections.filter(d => d.detection_type === typeFilter)
  }

  if (statusFilter) {
    filteredDetections = filteredDetections.filter(d => d.status === statusFilter)
  }

  if (managedFilter !== 'all') {
    filteredDetections = filteredDetections.filter(d =>
      managedFilter === 'managed' ? d.is_managed : !d.is_managed
    )
  }

  // Apply sorting
  filteredDetections.sort((a, b) => {
    let aVal: any = a[sortField]
    let bVal: any = b[sortField]

    if (sortField === 'discovered_at') {
      aVal = new Date(aVal).getTime()
      bVal = new Date(bVal).getTime()
    }

    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase()
      bVal = bVal.toLowerCase()
    }

    if (sortDirection === 'asc') {
      return aVal < bVal ? -1 : aVal > bVal ? 1 : 0
    } else {
      return aVal > bVal ? -1 : aVal < bVal ? 1 : 0
    }
  })

  // Get unique values for filters
  const detectionTypes = [...new Set(detections.map(d => d.detection_type))]
  const statuses = [...new Set(detections.map(d => d.status))]

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDirection('desc')
    }
  }

  const SortHeader = ({ field, children }: { field: SortField; children: React.ReactNode }) => (
    <th
      className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-700"
      onClick={() => handleSort(field)}
    >
      <div className="flex items-center space-x-1">
        <span>{children}</span>
        {sortField === field && (
          <ChevronDown className={`h-4 w-4 transition-transform ${sortDirection === 'asc' ? 'rotate-180' : ''}`} />
        )}
      </div>
    </th>
  )

  if (accountsLoading || isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!selectedAccount) {
    return (
      <div className="text-center py-12 card">
        <Shield className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-white">No account selected</h3>
        <p className="mt-1 text-sm text-gray-400">
          Select a cloud account from the sidebar to view its detections.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Detections</h1>
        <p className="text-gray-400">Security detections discovered in your cloud accounts</p>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-3 sm:gap-4 mb-6">
        <div className="relative w-full sm:flex-1 sm:min-w-[200px] sm:max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search detections..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-600 bg-gray-800 text-gray-100 placeholder-gray-500 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center gap-2 overflow-x-auto pb-1 sm:pb-0">
          <Filter className="h-4 w-4 text-gray-400 shrink-0" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="shrink-0 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Types</option>
            {detectionTypes.map(type => (
              <option key={type} value={type}>
                {detectionTypeConfig[type]?.label || type.replace(/_/g, ' ')}
              </option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="shrink-0 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Statuses</option>
            {statuses.map(status => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>

          {/* Managed/Custom filter toggle */}
          <div className="flex items-center rounded-lg border border-gray-600 overflow-hidden">
            <button
              onClick={() => setManagedFilter('all')}
              className={`px-3 py-2 text-sm transition-colors ${
                managedFilter === 'all'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setManagedFilter('managed')}
              className={`px-3 py-2 text-sm transition-colors flex items-center gap-1 ${
                managedFilter === 'managed'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              <Cloud className="h-3 w-3" />
              <span className="hidden sm:inline">{getProviderDisplayName(selectedAccount?.provider)}</span> Managed
            </button>
            <button
              onClick={() => setManagedFilter('custom')}
              className={`px-3 py-2 text-sm transition-colors ${
                managedFilter === 'custom'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              Custom
            </button>
          </div>

          {(typeFilter || statusFilter || search || managedFilter !== 'all') && (
            <button
              onClick={() => {
                setSearch('')
                setTypeFilter('')
                setStatusFilter('')
                setManagedFilter('all')
              }}
              className="shrink-0 text-sm text-blue-400 hover:text-blue-300"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-gray-400 mb-4">
        Showing {filteredDetections.length} of {regularDetections.length} detections
        {securityHubDetections.length > 0 && (
          <span className="ml-2 text-blue-400">
            + {securityHubDetections.length} Security Hub standard{securityHubDetections.length !== 1 ? 's' : ''}
          </span>
        )}
        {multiRegionGroups.length > 0 && (
          <span className="ml-2 text-cyan-400">
            + {multiRegionGroups.length} multi-region detection{multiRegionGroups.length !== 1 ? 's' : ''}
          </span>
        )}
      </p>

      {/* Aggregated Security Hub Standards */}
      {securityHubDetections.length > 0 && (
        <div className="mb-6 space-y-4">
          <h2 className="text-lg font-medium text-white flex items-center gap-2">
            <Lock className="h-5 w-5 text-blue-400" />
            Security Hub Standards
          </h2>
          {securityHubDetections.map((detection) => (
            <SecurityHubAggregatedCard
              key={detection.id}
              detection={{
                ...detection,
                raw_config: detection.raw_config as SecurityHubAggregatedConfig | undefined,
              }}
              onViewDetails={() => setSelectedDetection(detection)}
            />
          ))}
        </div>
      )}

      {/* Multi-Region Detections (aggregated by name) */}
      {multiRegionGroups.length > 0 && (
        <div className="mb-6 space-y-4">
          <h2 className="text-lg font-medium text-white flex items-center gap-2">
            <MapPin className="h-5 w-5 text-cyan-400" />
            Multi-Region Detections
          </h2>
          {multiRegionGroups.map((group) => (
            <RegionalAggregatedCard
              key={group.name}
              name={group.name}
              detectionType={group.detectionType}
              detections={group.detections}
              effectiveRegions={effectiveRegions}
              onViewDetails={(detection) => setSelectedDetection(detection)}
            />
          ))}
        </div>
      )}

      {/* Regular Detections Table (single-region only) */}
      {regularDetections.length > 0 && (securityHubDetections.length > 0 || multiRegionGroups.length > 0) && (
        <h2 className="text-lg font-medium text-white mb-4">Single-Region Detections</h2>
      )}
      {!filteredDetections.length && regularDetections.length === 0 && securityHubDetections.length === 0 && multiRegionGroups.length === 0 ? (
        <div className="text-center py-12 card">
          <Shield className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-white">No detections found</h3>
          <p className="mt-1 text-sm text-gray-400">
            Run a scan on your cloud accounts to discover detections.
          </p>
        </div>
      ) : !filteredDetections.length && regularDetections.length > 0 ? (
        <div className="text-center py-12 card">
          <Shield className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-white">No detections match your filters</h3>
          <p className="mt-1 text-sm text-gray-400">
            Try adjusting your search or filter criteria.
          </p>
        </div>
      ) : filteredDetections.length > 0 ? (
        <>
          {/* Mobile card view */}
          <div className="md:hidden space-y-3">
            {filteredDetections.map((detection) => (
              <DetectionCard
                key={detection.id}
                detection={detection}
                onClick={() => setSelectedDetection(detection)}
                provider={selectedAccount?.provider}
              />
            ))}
          </div>

          {/* Desktop table view */}
          <div className="hidden md:block card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-700">
                <thead className="bg-gray-700/30">
                  <tr>
                    <SortHeader field="name">Detection</SortHeader>
                    <SortHeader field="detection_type">Type</SortHeader>
                    <SortHeader field="region">Region</SortHeader>
                    <SortHeader field="status">Status</SortHeader>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Compliance
                    </th>
                    <SortHeader field="mapping_count">Mappings</SortHeader>
                    <SortHeader field="discovered_at">Discovered</SortHeader>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-gray-800 divide-y divide-gray-700">
                  {filteredDetections.map((detection) => (
                    <tr
                      key={detection.id}
                      className="hover:bg-gray-700 cursor-pointer"
                      onClick={() => setSelectedDetection(detection)}
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-white">{detection.name}</span>
                          <ManagedBadge isManaged={detection.is_managed} provider={selectedAccount?.provider} />
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <DetectionTypeBadge type={detection.detection_type} />
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">
                        {detection.region}
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                          detection.status === 'active'
                            ? 'bg-green-900/30 text-green-400'
                            : detection.status === 'disabled'
                            ? 'bg-gray-700/30 text-gray-400'
                            : 'bg-red-900/30 text-red-400'
                        }`}>
                          {detection.status}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <ComplianceIndicator evaluation={detection.evaluation_summary} />
                      </td>
                      <td className="px-6 py-4">
                        <span className={`text-sm ${
                          detection.mapping_count > 0
                            ? 'text-green-400 font-medium'
                            : 'text-gray-400'
                        }`}>
                          {detection.mapping_count} technique{detection.mapping_count !== 1 ? 's' : ''}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">
                        {new Date(detection.discovered_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedDetection(detection)
                          }}
                          className="p-2 text-gray-400 hover:text-blue-400 rounded-lg hover:bg-gray-700"
                          title="View details"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}

      {/* Detail Modal */}
      {selectedDetection && (
        <DetectionDetailModal
          detection={selectedDetection}
          onClose={() => setSelectedDetection(null)}
        />
      )}
    </div>
  )
}
