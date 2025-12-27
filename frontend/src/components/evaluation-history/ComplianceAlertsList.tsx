/**
 * Compliance Alerts List Component.
 *
 * Displays a list of compliance alerts with severity indicators,
 * acknowledgement workflow, and filtering options.
 */

import { useState } from 'react'
import { Bell, AlertTriangle, AlertCircle, Info, Check, Filter, Clock } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { EvaluationAlertItem, evaluationHistoryApi } from '../../services/api'

interface ComplianceAlertsListProps {
  alerts: EvaluationAlertItem[]
  isLoading?: boolean
  summary?: {
    total_alerts: number
    unacknowledged: number
    by_severity: Record<string, number>
  }
  accountId?: string
  onAcknowledge?: (alertId: string) => void
}

// Severity configuration
const severityConfig = {
  critical: {
    icon: AlertTriangle,
    colour: 'text-red-400',
    bgColour: 'bg-red-900/30',
    borderColour: 'border-l-red-500',
  },
  warning: {
    icon: AlertCircle,
    colour: 'text-yellow-400',
    bgColour: 'bg-yellow-900/30',
    borderColour: 'border-l-yellow-500',
  },
  info: {
    icon: Info,
    colour: 'text-blue-400',
    bgColour: 'bg-blue-900/30',
    borderColour: 'border-l-blue-500',
  },
}

function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity as keyof typeof severityConfig] || severityConfig.info
  const Icon = config.icon

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full ${config.bgColour} ${config.colour}`}>
      <Icon className="h-3 w-3" />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  )
}

function AlertCard({
  alert,
  onAcknowledge,
  isAcknowledging,
}: {
  alert: EvaluationAlertItem
  onAcknowledge: () => void
  isAcknowledging: boolean
}) {
  const config = severityConfig[alert.severity as keyof typeof severityConfig] || severityConfig.info

  return (
    <div
      className={`bg-gray-800 rounded-lg border-l-4 ${config.borderColour} p-4 hover:bg-gray-750 transition-colors`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          {/* Header */}
          <div className="flex items-center gap-3 mb-2">
            <SeverityBadge severity={alert.severity} />
            {alert.is_acknowledged && (
              <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full bg-gray-700 text-gray-400">
                <Check className="h-3 w-3" />
                Acknowledged
              </span>
            )}
          </div>

          {/* Title */}
          <h4 className="text-white font-medium mb-1">{alert.title}</h4>

          {/* Message */}
          <p className="text-sm text-gray-400 mb-3">{alert.message}</p>

          {/* Metadata */}
          <div className="flex flex-wrap items-center gap-4 text-xs text-gray-500">
            {alert.detection_name && (
              <span className="flex items-center gap-1">
                <span className="text-gray-600">Detection:</span>
                <span className="text-gray-400">{alert.detection_name}</span>
              </span>
            )}
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {new Date(alert.created_at).toLocaleString('en-GB', {
                day: 'numeric',
                month: 'short',
                hour: '2-digit',
                minute: '2-digit',
              })}
            </span>
            {alert.acknowledged_at && (
              <span className="text-gray-500">
                Acknowledged{' '}
                {new Date(alert.acknowledged_at).toLocaleString('en-GB', {
                  day: 'numeric',
                  month: 'short',
                })}
              </span>
            )}
          </div>
        </div>

        {/* Action */}
        {!alert.is_acknowledged && (
          <button
            onClick={onAcknowledge}
            disabled={isAcknowledging}
            className="flex-shrink-0 px-3 py-1.5 text-sm font-medium rounded-lg bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isAcknowledging ? 'Acknowledging...' : 'Acknowledge'}
          </button>
        )}
      </div>
    </div>
  )
}

export function ComplianceAlertsList({
  alerts,
  isLoading,
  summary,
  accountId,
  onAcknowledge,
}: ComplianceAlertsListProps) {
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null)
  const [showAcknowledged, setShowAcknowledged] = useState(false)
  const [acknowledgingId, setAcknowledgingId] = useState<string | null>(null)

  const queryClient = useQueryClient()

  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: string) => evaluationHistoryApi.acknowledgeAlert(alertId),
    onMutate: (alertId) => {
      setAcknowledgingId(alertId)
    },
    onSuccess: () => {
      // Invalidate alerts query to refresh the list
      if (accountId) {
        queryClient.invalidateQueries({ queryKey: ['evaluation-alerts', accountId] })
      }
      onAcknowledge?.(acknowledgingId!)
    },
    onSettled: () => {
      setAcknowledgingId(null)
    },
  })

  const filteredAlerts = alerts.filter((alert) => {
    if (filterSeverity && alert.severity !== filterSeverity) return false
    if (!showAcknowledged && alert.is_acknowledged) return false
    return true
  })

  if (isLoading) {
    return (
      <div className="card p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-700 rounded w-48 mb-4" />
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 bg-gray-700/50 rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bell className="h-5 w-5 text-gray-400" />
            <h3 className="text-lg font-semibold text-white">Compliance Alerts</h3>
            {summary && summary.unacknowledged > 0 && (
              <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-red-900/30 text-red-400">
                {summary.unacknowledged} unread
              </span>
            )}
          </div>

          {/* Filters */}
          <div className="flex items-center gap-2">
            {/* Severity Filter */}
            <div className="flex items-center gap-1 bg-gray-700/50 rounded-lg p-1">
              <button
                onClick={() => setFilterSeverity(null)}
                className={`px-2 py-1 text-xs rounded transition-colors ${
                  !filterSeverity
                    ? 'bg-gray-600 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                All
              </button>
              <button
                onClick={() => setFilterSeverity('critical')}
                className={`px-2 py-1 text-xs rounded transition-colors ${
                  filterSeverity === 'critical'
                    ? 'bg-red-900/50 text-red-400'
                    : 'text-gray-400 hover:text-red-400'
                }`}
              >
                Critical
              </button>
              <button
                onClick={() => setFilterSeverity('warning')}
                className={`px-2 py-1 text-xs rounded transition-colors ${
                  filterSeverity === 'warning'
                    ? 'bg-yellow-900/50 text-yellow-400'
                    : 'text-gray-400 hover:text-yellow-400'
                }`}
              >
                Warning
              </button>
              <button
                onClick={() => setFilterSeverity('info')}
                className={`px-2 py-1 text-xs rounded transition-colors ${
                  filterSeverity === 'info'
                    ? 'bg-blue-900/50 text-blue-400'
                    : 'text-gray-400 hover:text-blue-400'
                }`}
              >
                Info
              </button>
            </div>

            {/* Show Acknowledged Toggle */}
            <button
              onClick={() => setShowAcknowledged(!showAcknowledged)}
              className={`flex items-center gap-1 px-2 py-1 text-xs rounded-lg transition-colors ${
                showAcknowledged
                  ? 'bg-gray-600 text-white'
                  : 'bg-gray-700/50 text-gray-400 hover:text-white'
              }`}
            >
              <Filter className="h-3 w-3" />
              Show Acknowledged
            </button>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      {summary && (
        <div className="px-4 py-3 bg-gray-800/50 border-b border-gray-700 flex items-center gap-6 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Total:</span>
            <span className="text-white font-medium">{summary.total_alerts}</span>
          </div>
          {summary.by_severity?.critical > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-red-400">Critical:</span>
              <span className="text-red-400 font-medium">{summary.by_severity.critical}</span>
            </div>
          )}
          {summary.by_severity?.warning > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-yellow-400">Warning:</span>
              <span className="text-yellow-400 font-medium">{summary.by_severity.warning}</span>
            </div>
          )}
          {summary.by_severity?.info > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-blue-400">Info:</span>
              <span className="text-blue-400 font-medium">{summary.by_severity.info}</span>
            </div>
          )}
        </div>
      )}

      {/* Alerts List */}
      {filteredAlerts.length === 0 ? (
        <div className="p-8 text-center">
          <Bell className="h-12 w-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">
            {alerts.length === 0
              ? 'No alerts to display'
              : 'No alerts match the current filters'}
          </p>
        </div>
      ) : (
        <div className="p-4 space-y-3">
          {filteredAlerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onAcknowledge={() => acknowledgeMutation.mutate(alert.id)}
              isAcknowledging={acknowledgingId === alert.id}
            />
          ))}
        </div>
      )}
    </div>
  )
}
