import { useQuery } from '@tanstack/react-query'
import { Shield, Search, Filter, ChevronDown, Eye, Activity, Zap, CheckCircle, Lock, AlertTriangle } from 'lucide-react'
import { detectionsApi, Detection } from '../services/api'
import { useState } from 'react'
import DetectionDetailModal from '../components/DetectionDetailModal'

type SortField = 'name' | 'detection_type' | 'region' | 'status' | 'mapping_count' | 'discovered_at'
type SortDirection = 'asc' | 'desc'

const detectionTypeConfig: Record<string, { label: string; icon: React.ElementType; color: string; bgColor: string }> = {
  'cloudwatch_logs_insights': {
    label: 'CloudWatch Logs',
    icon: Activity,
    color: 'text-orange-400',
    bgColor: 'bg-orange-900/30'
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

export default function Detections() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [sortField, setSortField] = useState<SortField>('discovered_at')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [selectedDetection, setSelectedDetection] = useState<Detection | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['detections'],
    queryFn: () => detectionsApi.list({ limit: 100 }),
  })

  const detections = data?.items ?? []

  // Apply filters
  let filteredDetections = detections.filter(d =>
    d.name.toLowerCase().includes(search.toLowerCase())
  )

  if (typeFilter) {
    filteredDetections = filteredDetections.filter(d => d.detection_type === typeFilter)
  }

  if (statusFilter) {
    filteredDetections = filteredDetections.filter(d => d.status === statusFilter)
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

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
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
      <div className="flex flex-wrap items-center gap-4 mb-6">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search detections..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-gray-400" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
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
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Statuses</option>
            {statuses.map(status => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>

          {(typeFilter || statusFilter || search) && (
            <button
              onClick={() => {
                setSearch('')
                setTypeFilter('')
                setStatusFilter('')
              }}
              className="text-sm text-blue-600 hover:text-blue-700"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-gray-400 mb-4">
        Showing {filteredDetections.length} of {detections.length} detections
      </p>

      {/* Detections Table */}
      {!filteredDetections.length ? (
        <div className="text-center py-12 card">
          <Shield className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-white">No detections found</h3>
          <p className="mt-1 text-sm text-gray-400">
            {search || typeFilter || statusFilter
              ? 'Try adjusting your filters.'
              : 'Run a scan on your cloud accounts to discover detections.'}
          </p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-700">
              <thead className="bg-gray-700/30">
                <tr>
                  <SortHeader field="name">Detection</SortHeader>
                  <SortHeader field="detection_type">Type</SortHeader>
                  <SortHeader field="region">Region</SortHeader>
                  <SortHeader field="status">Status</SortHeader>
                  <SortHeader field="mapping_count">Mappings</SortHeader>
                  <SortHeader field="discovered_at">Discovered</SortHeader>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-700">
                {filteredDetections.map((detection) => (
                  <tr
                    key={detection.id}
                    className="hover:bg-gray-700 cursor-pointer"
                    onClick={() => setSelectedDetection(detection)}
                  >
                    <td className="px-6 py-4">
                      <div className="font-medium text-white">{detection.name}</div>
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
                        className="p-2 text-gray-400 hover:text-blue-600 rounded-lg hover:bg-gray-700"
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
      )}

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
