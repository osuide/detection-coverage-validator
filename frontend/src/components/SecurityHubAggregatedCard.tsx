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
  api_version: 'cspm_aggregated' | 'cspm_per_enabled_standard'
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
      className={`px-2 py-0.5 text-xs font-medium rounded-sm ${config.bgColour} ${config.colour}`}
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
      className="inline-flex items-center px-2 py-0.5 text-xs font-mono bg-blue-900/30 text-blue-400 border border-blue-700/50 rounded-sm hover:bg-blue-800/50 transition-colors"
    >
      {techniqueId}
      <ExternalLink className="h-2.5 w-2.5 ml-1" />
    </a>
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
        <div className="flex items-center gap-2 ml-4 shrink-0">
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
                className="flex items-center justify-between px-2 py-1 bg-gray-700/30 rounded-sm"
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
    const validApiVersion = config?.api_version === 'cspm_aggregated' ||
                            config?.api_version === 'cspm_per_enabled_standard'
    if (!config || !validApiVersion || !config.controls) {
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
  const isAggregated = config?.api_version === 'cspm_aggregated' ||
                       config?.api_version === 'cspm_per_enabled_standard'
  if (!config || !isAggregated) {
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
      {/* Compact card header */}
      <div
        className="px-4 py-3 cursor-pointer hover:bg-gray-700/30 transition-colors"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center justify-between gap-4">
          {/* Left: Icon + Title */}
          <div className="flex items-center gap-3 min-w-0">
            <div className="shrink-0 p-1.5 bg-blue-900/30 rounded-lg">
              <Lock className="h-5 w-5 text-blue-400" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-medium text-white truncate">
                {config.standard_name.replace(/-/g, ' ')}
              </h3>
              <div className="flex items-center gap-3 mt-0.5 text-xs text-gray-500">
                <span>{detection.region}</span>
                <span>•</span>
                <span>{new Date(detection.discovered_at).toLocaleDateString()}</span>
              </div>
            </div>
          </div>

          {/* Centre: Compact inline stats */}
          <div className="hidden md:flex items-center gap-6">
            {/* Controls */}
            <div className="flex items-center gap-2">
              <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className={`h-full ${enabledPercent >= 80 ? 'bg-green-500' : enabledPercent >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
                  style={{ width: `${enabledPercent}%` }}
                />
              </div>
              <span className="text-xs text-gray-400">
                {config.enabled_controls_count}/{config.total_controls_count}
              </span>
            </div>

            {/* Techniques */}
            <div className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-green-400" />
              <span className="text-sm font-medium text-green-400">{config.techniques_covered_count}</span>
              <span className="text-xs text-gray-500">techniques</span>
            </div>

            {/* Enablement % */}
            <span className={`text-sm font-semibold ${
              enabledPercent >= 80 ? 'text-green-400' : enabledPercent >= 50 ? 'text-yellow-400' : 'text-red-400'
            }`}>
              {enabledPercent}%
            </span>
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-1 shrink-0">
            {onViewDetails && (
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onViewDetails()
                }}
                className="p-1.5 text-gray-400 hover:text-blue-400 rounded-sm hover:bg-gray-700"
                title="View details"
              >
                <Eye className="h-4 w-4" />
              </button>
            )}
            <ChevronDown
              className={`h-4 w-4 text-gray-400 transition-transform ${
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
                className="border border-gray-600 bg-gray-700 text-gray-100 rounded-sm px-2 py-1 text-xs focus:ring-2 focus:ring-blue-500"
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
  return config?.api_version === 'cspm_aggregated' ||
         config?.api_version === 'cspm_per_enabled_standard'
}

export default SecurityHubAggregatedCard
