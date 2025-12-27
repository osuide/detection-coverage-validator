/**
 * Security Hub Aggregated Detection Card Component.
 *
 * Displays aggregated Security Hub standard detections with an expandable
 * controls section. Designed for CSPM (Cloud Security Posture Management)
 * aggregated data that shows all controls for a security standard.
 */

import { useState, useMemo } from 'react'
import {
  Lock,
  ChevronDown,
  Search,
  CheckCircle,
  XCircle,
  Shield,
  ExternalLink,
  Filter,
  MapPin,
  Clock,
  Eye,
} from 'lucide-react'

// Types for aggregated Security Hub detection
export interface SecurityHubControl {
  control_id: string
  status: 'ENABLED' | 'DISABLED'
  status_by_region?: Record<string, 'ENABLED' | 'DISABLED'>
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'
  title: string
  techniques?: string[]  // Optional - not always present from scanner
}

export interface SecurityHubAggregatedConfig {
  api_version: 'cspm_aggregated'
  standard_name: string
  enabled_controls_count: number
  disabled_controls_count: number
  total_controls_count: number
  techniques_covered_count: number
  techniques_covered: string[]
  controls: Record<string, SecurityHubControl>
}

interface SecurityHubAggregatedCardProps {
  detection: {
    id: string
    name: string
    detection_type: string
    status: string
    region: string
    mapping_count: number
    discovered_at: string
    raw_config?: SecurityHubAggregatedConfig
  }
  onViewDetails?: () => void
}

// Severity badge configuration
const severityConfig: Record<
  string,
  { colour: string; bgColour: string; order: number }
> = {
  CRITICAL: { colour: 'text-red-400', bgColour: 'bg-red-900/30', order: 0 },
  HIGH: { colour: 'text-orange-400', bgColour: 'bg-orange-900/30', order: 1 },
  MEDIUM: { colour: 'text-yellow-400', bgColour: 'bg-yellow-900/30', order: 2 },
  LOW: { colour: 'text-blue-400', bgColour: 'bg-blue-900/30', order: 3 },
  INFORMATIONAL: { colour: 'text-gray-400', bgColour: 'bg-gray-700/30', order: 4 },
}

function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity] || severityConfig.INFORMATIONAL
  return (
    <span
      className={`px-2 py-0.5 text-xs font-medium rounded ${config.bgColour} ${config.colour}`}
    >
      {severity}
    </span>
  )
}

function ControlStatusBadge({ status }: { status: 'ENABLED' | 'DISABLED' }) {
  if (status === 'ENABLED') {
    return (
      <span className="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full bg-green-900/30 text-green-400">
        <CheckCircle className="h-3 w-3 mr-1" />
        Enabled
      </span>
    )
  }
  return (
    <span className="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full bg-gray-700/30 text-gray-400">
      <XCircle className="h-3 w-3 mr-1" />
      Disabled
    </span>
  )
}

function TechniqueBadge({ techniqueId }: { techniqueId: string }) {
  return (
    <a
      href={`https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      className="inline-flex items-center px-2 py-0.5 text-xs font-mono bg-blue-900/30 text-blue-400 border border-blue-700/50 rounded hover:bg-blue-800/50 transition-colors"
    >
      {techniqueId}
      <ExternalLink className="h-2.5 w-2.5 ml-1" />
    </a>
  )
}

// Progress bar component
function CoverageProgressBar({
  enabled,
  total,
}: {
  enabled: number
  total: number
}) {
  const percent = total > 0 ? (enabled / total) * 100 : 0
  const getColour = () => {
    if (percent >= 80) return 'bg-green-500'
    if (percent >= 50) return 'bg-yellow-500'
    return 'bg-red-500'
  }

  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${getColour()} transition-all duration-300`}
          style={{ width: `${percent}%` }}
        />
      </div>
      <span className="text-sm font-medium text-gray-300 whitespace-nowrap">
        {enabled}/{total}
      </span>
    </div>
  )
}

// Individual control row in the accordion
function ControlRow({
  controlId,
  control,
}: {
  controlId: string
  control: SecurityHubControl
}) {
  const [showRegions, setShowRegions] = useState(false)
  const statusByRegion = control.status_by_region || {}
  const regionCount = Object.keys(statusByRegion).length
  const techniques = control.techniques || []

  return (
    <div className="border-b border-gray-700/50 last:border-b-0">
      <div
        className="flex items-center justify-between py-3 px-4 hover:bg-gray-700/30 cursor-pointer"
        onClick={() => setShowRegions(!showRegions)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-mono text-blue-400">{controlId}</span>
            <ControlStatusBadge status={control.status} />
            <SeverityBadge severity={control.severity} />
            {regionCount > 1 && (
              <span className="text-xs text-gray-500">
                ({regionCount} regions)
              </span>
            )}
          </div>
          <p className="text-sm text-gray-400 mt-1 truncate">{control.title}</p>
        </div>
        <div className="flex items-center gap-2 ml-4 flex-shrink-0">
          {techniques.length > 0 && (
            <div className="flex flex-wrap gap-1 max-w-xs">
              {techniques.slice(0, 3).map((techniqueId) => (
                <TechniqueBadge key={techniqueId} techniqueId={techniqueId} />
              ))}
              {techniques.length > 3 && (
                <span className="text-xs text-gray-500">
                  +{techniques.length - 3} more
                </span>
              )}
            </div>
          )}
          {regionCount > 1 && (
            <ChevronDown
              className={`h-4 w-4 text-gray-400 transition-transform ${
                showRegions ? 'rotate-180' : ''
              }`}
            />
          )}
        </div>
      </div>

      {/* Region details accordion */}
      {showRegions && regionCount > 1 && (
        <div className="bg-gray-800/50 px-6 py-3 border-t border-gray-700/50">
          <div className="text-xs text-gray-500 mb-2 flex items-center gap-1">
            <MapPin className="h-3 w-3" />
            Status by Region
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {Object.entries(statusByRegion).map(([region, status]) => (
              <div
                key={region}
                className="flex items-center justify-between px-2 py-1 bg-gray-700/30 rounded"
              >
                <span className="text-xs text-gray-400">{region}</span>
                <span
                  className={`text-xs font-medium ${
                    status === 'ENABLED' ? 'text-green-400' : 'text-gray-500'
                  }`}
                >
                  {status === 'ENABLED' ? 'On' : 'Off'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function SecurityHubAggregatedCard({
  detection,
  onViewDetails,
}: SecurityHubAggregatedCardProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'enabled' | 'disabled'>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const config = detection.raw_config

  // Parse and filter controls - must be before early return for hooks rules
  const { filteredControls, controlStats } = useMemo(() => {
    // Handle missing/invalid config
    if (!config || config.api_version !== 'cspm_aggregated' || !config.controls) {
      return { filteredControls: [], controlStats: { severities: [], filteredCount: 0 } }
    }

    // Controls is an array of objects, each with control_id field
    const controlsArray = Array.isArray(config.controls) ? config.controls : []

    // Get unique severities for filter
    const severities = new Set(controlsArray.map((c) => c.severity))

    // Filter controls
    const filtered = controlsArray.filter((control) => {
      const controlId = control.control_id || ''
      const techniques = control.techniques || []

      // Search filter
      const matchesSearch =
        searchTerm === '' ||
        controlId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (control.title || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        techniques.some((t: string) =>
          t.toLowerCase().includes(searchTerm.toLowerCase())
        )

      // Status filter - check status_by_region for any enabled region
      const isEnabled = control.status_by_region
        ? Object.values(control.status_by_region).some((s) => s === 'ENABLED')
        : control.status === 'ENABLED'
      const matchesStatus =
        statusFilter === 'all' ||
        (statusFilter === 'enabled' && isEnabled) ||
        (statusFilter === 'disabled' && !isEnabled)

      // Severity filter
      const matchesSeverity =
        severityFilter === 'all' || control.severity === severityFilter

      return matchesSearch && matchesStatus && matchesSeverity
    })

    // Sort: enabled first, then by severity, then by control ID
    filtered.sort((a, b) => {
      // Status: enabled first
      const aEnabled = a.status_by_region
        ? Object.values(a.status_by_region).some((s) => s === 'ENABLED')
        : a.status === 'ENABLED'
      const bEnabled = b.status_by_region
        ? Object.values(b.status_by_region).some((s) => s === 'ENABLED')
        : b.status === 'ENABLED'
      if (aEnabled !== bEnabled) {
        return aEnabled ? -1 : 1
      }
      // Severity order
      const severityDiff =
        (severityConfig[a.severity]?.order ?? 5) -
        (severityConfig[b.severity]?.order ?? 5)
      if (severityDiff !== 0) return severityDiff
      // Control ID alphabetically
      return (a.control_id || '').localeCompare(b.control_id || '')
    })

    return {
      filteredControls: filtered,
      controlStats: {
        severities: Array.from(severities),
        filteredCount: filtered.length,
      },
    }
  }, [config, searchTerm, statusFilter, severityFilter])

  // If no aggregated config, render nothing (let parent handle it)
  if (!config || config.api_version !== 'cspm_aggregated') {
    return null
  }

  const enabledPercent =
    config.total_controls_count > 0
      ? Math.round(
          (config.enabled_controls_count / config.total_controls_count) * 100
        )
      : 0

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      {/* Main card header - always visible */}
      <div
        className="p-4 cursor-pointer hover:bg-gray-700/30 transition-colors"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-start justify-between">
          {/* Left side: Standard info */}
          <div className="flex items-start gap-4 flex-1 min-w-0">
            {/* Icon */}
            <div className="flex-shrink-0 p-2 bg-blue-900/30 rounded-lg">
              <Lock className="h-6 w-6 text-blue-400" />
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-lg font-medium text-white">
                  {config.standard_name.replace(/-/g, ' ')}
                </h3>
                <span className="inline-flex items-center px-2.5 py-1 text-xs font-medium rounded-full bg-blue-900/30 text-blue-400">
                  <Shield className="h-3 w-3 mr-1" />
                  Security Hub Standard
                </span>
              </div>

              {/* Metrics row */}
              <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Controls progress */}
                <div>
                  <div className="text-xs text-gray-500 mb-1">
                    Controls Enabled
                  </div>
                  <CoverageProgressBar
                    enabled={config.enabled_controls_count}
                    total={config.total_controls_count}
                  />
                </div>

                {/* Techniques covered */}
                <div>
                  <div className="text-xs text-gray-500 mb-1">
                    Techniques Covered
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-lg font-semibold text-green-400">
                      {config.techniques_covered_count}
                    </span>
                    <span className="text-sm text-gray-400">
                      MITRE ATT&CK techniques
                    </span>
                  </div>
                </div>

                {/* Coverage percentage */}
                <div>
                  <div className="text-xs text-gray-500 mb-1">
                    Overall Enablement
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-lg font-semibold ${
                        enabledPercent >= 80
                          ? 'text-green-400'
                          : enabledPercent >= 50
                          ? 'text-yellow-400'
                          : 'text-red-400'
                      }`}
                    >
                      {enabledPercent}%
                    </span>
                    {config.disabled_controls_count > 0 && (
                      <span className="text-sm text-gray-500">
                        ({config.disabled_controls_count} disabled)
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Discovered date and region */}
              <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
                <span className="flex items-center gap-1">
                  <MapPin className="h-3 w-3" />
                  {detection.region}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  Discovered {new Date(detection.discovered_at).toLocaleDateString()}
                </span>
              </div>
            </div>
          </div>

          {/* Right side: Actions */}
          <div className="flex items-center gap-2 ml-4 flex-shrink-0">
            {onViewDetails && (
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onViewDetails()
                }}
                className="p-2 text-gray-400 hover:text-blue-400 rounded-lg hover:bg-gray-700"
                title="View details"
              >
                <Eye className="h-4 w-4" />
              </button>
            )}
            <ChevronDown
              className={`h-5 w-5 text-gray-400 transition-transform ${
                isExpanded ? 'rotate-180' : ''
              }`}
            />
          </div>
        </div>
      </div>

      {/* Expanded controls section */}
      {isExpanded && (
        <div className="border-t border-gray-700">
          {/* Filters */}
          <div className="p-4 bg-gray-800/50 border-b border-gray-700 space-y-3">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search controls by ID, title, or technique..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                className="w-full pl-10 pr-4 py-2 border border-gray-600 bg-gray-700 text-gray-100 placeholder-gray-500 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              />
            </div>

            {/* Filter chips */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-gray-400" />
                <span className="text-xs text-gray-400">Filters:</span>
              </div>

              {/* Status filter */}
              <div className="flex gap-1">
                {(['all', 'enabled', 'disabled'] as const).map((status) => (
                  <button
                    key={status}
                    onClick={(e) => {
                      e.stopPropagation()
                      setStatusFilter(status)
                    }}
                    className={`px-2 py-1 text-xs rounded transition-colors ${
                      statusFilter === status
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                    }`}
                  >
                    {status === 'all'
                      ? 'All'
                      : status === 'enabled'
                      ? `Enabled (${config.enabled_controls_count})`
                      : `Disabled (${config.disabled_controls_count})`}
                  </button>
                ))}
              </div>

              {/* Severity filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                className="border border-gray-600 bg-gray-700 text-gray-100 rounded px-2 py-1 text-xs focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Severities</option>
                {controlStats.severities.map((sev) => (
                  <option key={sev} value={sev}>
                    {sev}
                  </option>
                ))}
              </select>

              {/* Results count */}
              <span className="text-xs text-gray-500 ml-auto">
                Showing {controlStats.filteredCount} of{' '}
                {config.total_controls_count} controls
              </span>
            </div>
          </div>

          {/* Controls list */}
          <div className="max-h-96 overflow-y-auto">
            {filteredControls.length > 0 ? (
              filteredControls.map((control) => (
                <ControlRow
                  key={control.control_id}
                  controlId={control.control_id}
                  control={control}
                />
              ))
            ) : (
              <div className="py-8 text-center text-gray-500">
                <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No controls match your filters</p>
              </div>
            )}
          </div>

          {/* Techniques summary footer */}
          {config.techniques_covered.length > 0 && (
            <div className="p-4 bg-gray-800/50 border-t border-gray-700">
              <div className="text-xs text-gray-500 mb-2">
                Techniques Covered by This Standard
              </div>
              <div className="flex flex-wrap gap-1">
                {config.techniques_covered.slice(0, 10).map((techniqueId) => (
                  <TechniqueBadge key={techniqueId} techniqueId={techniqueId} />
                ))}
                {config.techniques_covered.length > 10 && (
                  <span className="text-xs text-gray-500 self-center ml-1">
                    +{config.techniques_covered.length - 10} more techniques
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Helper function to check if a detection is an aggregated Security Hub detection
export function isSecurityHubAggregated(detection: {
  detection_type: string
  raw_config?: Record<string, unknown>
}): boolean {
  if (detection.detection_type !== 'security_hub') return false
  const config = detection.raw_config as SecurityHubAggregatedConfig | undefined
  return config?.api_version === 'cspm_aggregated'
}

export default SecurityHubAggregatedCard
