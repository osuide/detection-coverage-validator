/**
 * Compliance History Table Component.
 *
 * Displays a timeline of compliance state changes with timestamps,
 * previous/current states, and filtering options.
 */

import { useState } from 'react'
import { History, ArrowRight, Filter, ChevronDown, ChevronUp } from 'lucide-react'
import { EvaluationHistoryItem } from '../../services/api'

interface ComplianceHistoryTableProps {
  history: EvaluationHistoryItem[]
  isLoading?: boolean
  detectionName?: string
  pagination?: {
    offset: number
    limit: number
    total: number
    has_more: boolean
  }
  onPageChange?: (offset: number) => void
}

// Status badge styling
const statusConfig: Record<string, { colour: string; bgColour: string }> = {
  COMPLIANT: { colour: 'text-green-400', bgColour: 'bg-green-900/30' },
  OK: { colour: 'text-green-400', bgColour: 'bg-green-900/30' },
  ENABLED: { colour: 'text-green-400', bgColour: 'bg-green-900/30' },
  NON_COMPLIANT: { colour: 'text-red-400', bgColour: 'bg-red-900/30' },
  ALARM: { colour: 'text-red-400', bgColour: 'bg-red-900/30' },
  DISABLED: { colour: 'text-gray-400', bgColour: 'bg-gray-700/30' },
  INSUFFICIENT_DATA: { colour: 'text-yellow-400', bgColour: 'bg-yellow-900/30' },
  UNKNOWN: { colour: 'text-gray-400', bgColour: 'bg-gray-700/30' },
}

function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || statusConfig.UNKNOWN
  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${config.bgColour} ${config.colour}`}>
      {status}
    </span>
  )
}

function StateTransition({ from, to }: { from: string | null; to: string }) {
  if (!from) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-gray-500 text-xs">Initial</span>
        <ArrowRight className="h-3 w-3 text-gray-500" />
        <StatusBadge status={to} />
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <StatusBadge status={from} />
      <ArrowRight className="h-3 w-3 text-gray-500" />
      <StatusBadge status={to} />
    </div>
  )
}

export function ComplianceHistoryTable({
  history,
  isLoading,
  detectionName,
  pagination,
  onPageChange,
}: ComplianceHistoryTableProps) {
  const [showChangesOnly, setShowChangesOnly] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const filteredHistory = showChangesOnly
    ? history.filter((h) => h.status_changed)
    : history

  if (isLoading) {
    return (
      <div className="card">
        <div className="p-4 border-b border-gray-700">
          <div className="h-6 bg-gray-700 rounded w-48 animate-pulse" />
        </div>
        <div className="divide-y divide-gray-700">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="p-4 animate-pulse">
              <div className="flex items-center gap-4">
                <div className="h-4 bg-gray-700 rounded w-32" />
                <div className="h-4 bg-gray-700 rounded w-24" />
                <div className="h-4 bg-gray-700 rounded w-16 ml-auto" />
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (!history.length) {
    return (
      <div className="card p-6">
        <div className="flex items-center gap-2 mb-4">
          <History className="h-5 w-5 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">State History</h3>
        </div>
        <div className="flex items-center justify-center h-32 text-gray-400">
          <p>No history records available yet.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-gray-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <History className="h-5 w-5 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">
            State History
            {detectionName && (
              <span className="text-gray-400 font-normal text-sm ml-2">
                for {detectionName}
              </span>
            )}
          </h3>
        </div>

        {/* Filter Toggle */}
        <button
          onClick={() => setShowChangesOnly(!showChangesOnly)}
          className={`flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg transition-colors ${
            showChangesOnly
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          <Filter className="h-4 w-4" />
          Changes Only
        </button>
      </div>

      {/* Table */}
      <div className="divide-y divide-gray-700">
        {filteredHistory.map((item) => {
          const isExpanded = expandedId === item.id

          return (
            <div key={item.id} className="hover:bg-gray-700/30 transition-colors">
              <div
                className="p-4 cursor-pointer"
                onClick={() => setExpandedId(isExpanded ? null : item.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    {/* Timestamp */}
                    <div className="w-40 flex-shrink-0">
                      <p className="text-sm text-white">
                        {new Date(item.timestamp).toLocaleDateString('en-GB', {
                          day: 'numeric',
                          month: 'short',
                          year: 'numeric',
                        })}
                      </p>
                      <p className="text-xs text-gray-400">
                        {new Date(item.timestamp).toLocaleTimeString('en-GB', {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </p>
                    </div>

                    {/* State Transition */}
                    <StateTransition from={item.previous_status} to={item.evaluation_status} />
                  </div>

                  <div className="flex items-center gap-3">
                    {/* Changed Badge */}
                    {item.status_changed && (
                      <span className="px-2 py-1 text-xs font-medium rounded-full bg-yellow-900/30 text-yellow-400">
                        Changed
                      </span>
                    )}

                    {/* Expand Icon */}
                    {item.evaluation_summary && (
                      isExpanded ? (
                        <ChevronUp className="h-4 w-4 text-gray-400" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-gray-400" />
                      )
                    )}
                  </div>
                </div>
              </div>

              {/* Expanded Details */}
              {isExpanded && item.evaluation_summary && (
                <div className="px-4 pb-4">
                  <div className="bg-gray-800 rounded-lg p-3 ml-44">
                    <p className="text-xs text-gray-400 mb-2">Evaluation Details</p>
                    <pre className="text-xs text-gray-300 overflow-x-auto">
                      {JSON.stringify(item.evaluation_summary, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Pagination */}
      {pagination && pagination.total > pagination.limit && (
        <div className="p-4 border-t border-gray-700 flex items-center justify-between">
          <p className="text-sm text-gray-400">
            Showing {pagination.offset + 1} to{' '}
            {Math.min(pagination.offset + pagination.limit, pagination.total)} of{' '}
            {pagination.total} records
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onPageChange?.(Math.max(0, pagination.offset - pagination.limit))}
              disabled={pagination.offset === 0}
              className="px-3 py-1.5 text-sm rounded-lg bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              onClick={() => onPageChange?.(pagination.offset + pagination.limit)}
              disabled={!pagination.has_more}
              className="px-3 py-1.5 text-sm rounded-lg bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Summary Footer */}
      <div className="p-4 border-t border-gray-700 bg-gray-800/50">
        <div className="flex items-center justify-center gap-6 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Total Records:</span>
            <span className="text-white font-medium">{pagination?.total || history.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">State Changes:</span>
            <span className="text-yellow-400 font-medium">
              {history.filter((h) => h.status_changed).length}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
