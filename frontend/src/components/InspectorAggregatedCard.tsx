/**
 * Regional Aggregated Detection Card Component.
 *
 * Displays detections aggregated by name across regions.
 * Many AWS services (Inspector, EventBridge, CloudWatch, etc.) run per-region
 * but represent the same detection capability, so we aggregate them
 * to avoid duplicate entries in the UI.
 */

import { useState } from 'react'
import {
  Search,
  ChevronDown,
  CheckCircle,
  XCircle,
  Shield,
  MapPin,
  Eye,
  Activity,
  Zap,
  Bell,
  AlertTriangle,
} from 'lucide-react'
import { Detection } from '../services/api'

// Detection type configuration for icons and colours
const detectionTypeConfig: Record<
  string,
  { icon: React.ElementType; colour: string; bgColour: string }
> = {
  inspector_finding: {
    icon: Search,
    colour: 'text-cyan-400',
    bgColour: 'bg-cyan-900/30',
  },
  eventbridge_rule: {
    icon: Zap,
    colour: 'text-purple-400',
    bgColour: 'bg-purple-900/30',
  },
  cloudwatch_alarm: {
    icon: Bell,
    colour: 'text-amber-400',
    bgColour: 'bg-amber-900/30',
  },
  cloudwatch_logs_insights: {
    icon: Activity,
    colour: 'text-orange-400',
    bgColour: 'bg-orange-900/30',
  },
  guardduty_finding: {
    icon: Shield,
    colour: 'text-red-400',
    bgColour: 'bg-red-900/30',
  },
  config_rule: {
    icon: CheckCircle,
    colour: 'text-green-400',
    bgColour: 'bg-green-900/30',
  },
}

interface RegionalAggregatedCardProps {
  /** Detection name */
  name: string
  /** Detection type (for icon/styling) */
  detectionType: string
  /** All detection instances with this name across regions */
  detections: Detection[]
  /** Callback when user clicks to view details of a specific region's detection */
  onViewDetails?: (detection: Detection) => void
}

export function RegionalAggregatedCard({
  name,
  detectionType,
  detections,
  onViewDetails,
}: RegionalAggregatedCardProps) {
  const [isExpanded, setIsExpanded] = useState(false)

  // Get type config
  const typeConfig = detectionTypeConfig[detectionType] || {
    icon: AlertTriangle,
    colour: 'text-gray-400',
    bgColour: 'bg-gray-700/30',
  }
  const TypeIcon = typeConfig.icon

  // Calculate aggregated stats
  const activeRegions = detections.filter((d) => d.status === 'active')
  const totalMappings = Math.max(...detections.map((d) => d.mapping_count || 0))

  // Get the most recent discovered_at
  const latestDiscovered = detections.reduce((latest, d) => {
    const date = new Date(d.discovered_at)
    return date > latest ? date : latest
  }, new Date(0))

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      {/* Card header */}
      <div
        className="px-4 py-3 cursor-pointer hover:bg-gray-700/30 transition-colors"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center justify-between gap-4">
          {/* Left: Icon + Title */}
          <div className="flex items-center gap-3 min-w-0">
            <div className={`shrink-0 p-1.5 ${typeConfig.bgColour} rounded-lg`}>
              <TypeIcon className={`h-5 w-5 ${typeConfig.colour}`} />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-medium text-white truncate">{name}</h3>
              <div className="flex items-center gap-3 mt-0.5 text-xs text-gray-500">
                <span className="inline-flex items-center">
                  <MapPin className="h-3 w-3 mr-1" />
                  {detections.length} region{detections.length !== 1 ? 's' : ''}
                </span>
                <span>•</span>
                <span>{latestDiscovered.toLocaleDateString()}</span>
              </div>
            </div>
          </div>

          {/* Centre: Stats */}
          <div className="hidden md:flex items-center gap-6">
            {/* Active regions */}
            <div className="flex items-center gap-2">
              <span
                className={`text-sm font-medium ${
                  activeRegions.length === detections.length
                    ? 'text-green-400'
                    : activeRegions.length > 0
                    ? 'text-yellow-400'
                    : 'text-red-400'
                }`}
              >
                {activeRegions.length}/{detections.length}
              </span>
              <span className="text-xs text-gray-500">active</span>
            </div>

            {/* Techniques */}
            <div className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-green-400" />
              <span className="text-sm font-medium text-green-400">
                {totalMappings}
              </span>
              <span className="text-xs text-gray-500">techniques</span>
            </div>
          </div>

          {/* Right: Expand */}
          <div className="flex items-center gap-1 shrink-0">
            <ChevronDown
              className={`h-4 w-4 text-gray-400 transition-transform ${
                isExpanded ? 'rotate-180' : ''
              }`}
            />
          </div>
        </div>
      </div>

      {/* Expanded region details */}
      {isExpanded && (
        <div className="border-t border-gray-700">
          <div className="p-4 bg-gray-800/50">
            <div className="text-xs text-gray-500 mb-3 flex items-center gap-1">
              <MapPin className="h-3 w-3" />
              Regional Coverage
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {detections
                .sort((a, b) => a.region.localeCompare(b.region))
                .map((detection) => (
                  <div
                    key={detection.id}
                    className="flex items-center justify-between px-3 py-2 bg-gray-700/30 rounded-lg hover:bg-gray-700/50 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      {detection.status === 'active' ? (
                        <CheckCircle className="h-4 w-4 text-green-400" />
                      ) : (
                        <XCircle className="h-4 w-4 text-gray-500" />
                      )}
                      <span className="text-sm text-gray-300">
                        {detection.region}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">
                        {detection.mapping_count} techniques
                      </span>
                      {onViewDetails && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            onViewDetails(detection)
                          }}
                          className="p-1 text-gray-400 hover:text-blue-400 rounded hover:bg-gray-600"
                          title="View details"
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * Result of grouping detections by name.
 */
export interface DetectionGroup {
  name: string
  detectionType: string
  detections: Detection[]
}

/**
 * Groups detections by name for regional aggregation.
 * Returns groups that have multiple regions (for aggregation)
 * and single detections that remain in the regular list.
 *
 * Note: Security Hub aggregated detections should be filtered out
 * before calling this function.
 */
export function groupDetectionsByName(detections: Detection[]): {
  multiRegionGroups: DetectionGroup[]
  singleRegionDetections: Detection[]
} {
  const groupMap = new Map<string, Detection[]>()

  // Group by name
  detections.forEach((d) => {
    const existing = groupMap.get(d.name) || []
    groupMap.set(d.name, [...existing, d])
  })

  const multiRegionGroups: DetectionGroup[] = []
  const singleRegionDetections: Detection[] = []

  groupMap.forEach((group, name) => {
    if (group.length > 1) {
      // Multiple regions - aggregate
      multiRegionGroups.push({
        name,
        detectionType: group[0].detection_type,
        detections: group,
      })
    } else {
      // Single region - keep in regular list
      singleRegionDetections.push(group[0])
    }
  })

  // Sort groups by name
  multiRegionGroups.sort((a, b) => a.name.localeCompare(b.name))

  return { multiRegionGroups, singleRegionDetections }
}

// Keep these exports for backwards compatibility
export const InspectorAggregatedCard = RegionalAggregatedCard
export const groupInspectorDetections = (detections: Detection[]) => {
  const result = groupDetectionsByName(
    detections.filter((d) => d.detection_type === 'inspector_finding')
  )
  const map = new Map<string, Detection[]>()
  result.multiRegionGroups.forEach((g) => map.set(g.name, g.detections))
  return map
}

export default RegionalAggregatedCard
