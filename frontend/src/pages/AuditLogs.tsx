import { useState, useEffect } from 'react'
import {
  FileText,
  ChevronLeft,
  ChevronRight,
  Clock,
  User,
  Activity,
  Filter,
  X,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '../contexts/AuthContext'
import {
  auditApi,
  AuditLogEntry,
  AuditStats,
  AuditAction,
  ListAuditLogsParams,
} from '../services/auditApi'

// Action category colors
const actionCategoryColors: Record<string, string> = {
  user: 'bg-blue-900/30 text-blue-400',
  member: 'bg-green-900/30 text-green-400',
  org: 'bg-purple-900/30 text-purple-400',
  api_key: 'bg-yellow-900/30 text-yellow-400',
  account: 'bg-cyan-900/30 text-cyan-400',
  scan: 'bg-orange-900/30 text-orange-400',
  detection: 'bg-pink-900/30 text-pink-400',
}

function getActionColor(action: string): string {
  const category = action.split('.')[0]
  return actionCategoryColors[category] || 'bg-gray-700/30 text-gray-400'
}

export default function AuditLogs() {
  const { accessToken } = useAuth()
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [stats, setStats] = useState<AuditStats | null>(null)
  const [actionTypes, setActionTypes] = useState<AuditAction[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Pagination
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)
  const pageSize = 25

  // Filters
  const [showFilters, setShowFilters] = useState(false)
  const [filterAction, setFilterAction] = useState<string>('')
  const [filterStartDate, setFilterStartDate] = useState<string>('')
  const [filterEndDate, setFilterEndDate] = useState<string>('')

  // Detail modal
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null)

  useEffect(() => {
    loadData()
  }, [accessToken])

  useEffect(() => {
    if (accessToken) {
      loadLogs()
    }
  }, [page, filterAction, filterStartDate, filterEndDate])

  const loadData = async () => {
    if (!accessToken) return

    setIsLoading(true)
    setError(null)

    try {
      const [statsData, actionsData] = await Promise.all([
        auditApi.getStats(accessToken),
        auditApi.getActionTypes(accessToken),
      ])
      setStats(statsData)
      setActionTypes(actionsData.actions)
      await loadLogs()
    } catch (err) {
      console.error('Failed to load audit data:', err)
      setError('Failed to load audit logs')
    } finally {
      setIsLoading(false)
    }
  }

  const loadLogs = async () => {
    if (!accessToken) return

    try {
      const params: ListAuditLogsParams = {
        page,
        page_size: pageSize,
      }
      if (filterAction) params.action = filterAction
      if (filterStartDate) params.start_date = filterStartDate
      if (filterEndDate) params.end_date = filterEndDate

      const data = await auditApi.getAuditLogs(accessToken, params)
      setLogs(data.items)
      setTotalPages(data.pages)
      setTotal(data.total)
    } catch (err) {
      console.error('Failed to load logs:', err)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  const formatAction = (action: string) => {
    return action.replace('.', ' ').replace(/_/g, ' ')
  }

  const clearFilters = () => {
    setFilterAction('')
    setFilterStartDate('')
    setFilterEndDate('')
    setPage(1)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-cyan-500 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Audit Logs</h1>
        <p className="mt-1 text-sm text-gray-400">
          Track all activity and changes in your organization
        </p>
      </div>

      {/* Error message */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-400 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gray-800 rounded-xl shadow-xs border border-gray-700 p-4">
            <div className="flex items-center">
              <div className="p-2 bg-blue-900/30 rounded-lg">
                <Activity className="h-5 w-5 text-blue-400" />
              </div>
              <div className="ml-3">
                <p className="text-sm text-gray-400">Total Events</p>
                <p className="text-xl font-semibold text-white">{stats.total_events.toLocaleString()}</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-800 rounded-xl shadow-xs border border-gray-700 p-4">
            <div className="flex items-center">
              <div className="p-2 bg-green-900/30 rounded-lg">
                <Clock className="h-5 w-5 text-green-400" />
              </div>
              <div className="ml-3">
                <p className="text-sm text-gray-400">Today</p>
                <p className="text-xl font-semibold text-white">{stats.events_today.toLocaleString()}</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-800 rounded-xl shadow-xs border border-gray-700 p-4">
            <div className="flex items-center">
              <div className="p-2 bg-purple-900/30 rounded-lg">
                <FileText className="h-5 w-5 text-purple-400" />
              </div>
              <div className="ml-3">
                <p className="text-sm text-gray-400">This Week</p>
                <p className="text-xl font-semibold text-white">{stats.events_this_week.toLocaleString()}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-gray-800 rounded-xl shadow-xs border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
          <div className="flex items-center">
            <FileText className="h-5 w-5 text-gray-400 mr-2" />
            <h2 className="text-lg font-medium text-white">Activity Log</h2>
            <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-gray-700/30 text-gray-400 rounded-full">
              {total.toLocaleString()} events
            </span>
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={clsx(
              'flex items-center px-3 py-1.5 text-sm rounded-lg',
              showFilters || filterAction || filterStartDate || filterEndDate
                ? 'bg-cyan-900/30 text-cyan-400'
                : 'bg-gray-700/30 text-gray-400 hover:bg-gray-700'
            )}
          >
            <Filter className="h-4 w-4 mr-1" />
            Filters
            {(filterAction || filterStartDate || filterEndDate) && (
              <span className="ml-1 px-1.5 py-0.5 bg-cyan-600 text-white text-xs rounded-full">
                {[filterAction, filterStartDate, filterEndDate].filter(Boolean).length}
              </span>
            )}
          </button>
        </div>

        {showFilters && (
          <div className="px-6 py-4 bg-gray-700/30 border-b border-gray-700">
            <div className="flex flex-wrap items-center gap-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Action Type</label>
                <select
                  value={filterAction}
                  onChange={(e) => {
                    setFilterAction(e.target.value)
                    setPage(1)
                  }}
                  className="px-3 py-1.5 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg text-sm focus:ring-cyan-500 focus:border-cyan-500"
                >
                  <option value="">All actions</option>
                  {actionTypes.map((action) => (
                    <option key={action.value} value={action.value}>
                      {action.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Start Date</label>
                <input
                  type="datetime-local"
                  value={filterStartDate}
                  onChange={(e) => {
                    setFilterStartDate(e.target.value)
                    setPage(1)
                  }}
                  className="px-3 py-1.5 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg text-sm focus:ring-cyan-500 focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">End Date</label>
                <input
                  type="datetime-local"
                  value={filterEndDate}
                  onChange={(e) => {
                    setFilterEndDate(e.target.value)
                    setPage(1)
                  }}
                  className="px-3 py-1.5 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg text-sm focus:ring-cyan-500 focus:border-cyan-500"
                />
              </div>
              {(filterAction || filterStartDate || filterEndDate) && (
                <button
                  onClick={clearFilters}
                  className="px-3 py-1.5 text-sm text-gray-400 hover:text-white"
                >
                  Clear filters
                </button>
              )}
            </div>
          </div>
        )}

        {/* Logs table */}
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-700">
            <thead className="bg-gray-700/30">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Timestamp
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Action
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actor
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  IP Address
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="bg-gray-800 divide-y divide-gray-700">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-gray-400">
                    No audit logs found
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-gray-700 cursor-pointer"
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                      {formatDate(log.created_at)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={clsx(
                        'px-2 py-1 text-xs font-medium rounded-full capitalize',
                        getActionColor(log.action)
                      )}>
                        {formatAction(log.action)}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {log.actor ? (
                        <div className="flex items-center">
                          <div className="h-8 w-8 rounded-full bg-gray-700/30 flex items-center justify-center">
                            <User className="h-4 w-4 text-gray-400" />
                          </div>
                          <div className="ml-3">
                            <div className="text-sm font-medium text-white">{log.actor.full_name}</div>
                            <div className="text-xs text-gray-400">{log.actor.email}</div>
                          </div>
                        </div>
                      ) : (
                        <span className="text-sm text-gray-400">System</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400 font-mono">
                      {log.ip_address || '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={clsx(
                        'px-2 py-1 text-xs font-medium rounded-full',
                        log.success
                          ? 'bg-green-900/30 text-green-400'
                          : 'bg-red-900/30 text-red-400'
                      )}>
                        {log.success ? 'Success' : 'Failed'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-between">
            <div className="text-sm text-gray-400">
              Page {page} of {totalPages}
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setPage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="p-1 rounded-lg hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="h-5 w-5" />
              </button>
              <button
                onClick={() => setPage(Math.min(totalPages, page + 1))}
                disabled={page === totalPages}
                className="p-1 rounded-lg hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight className="h-5 w-5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl shadow-xl max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h2 className="text-lg font-medium text-white">Event Details</h2>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-gray-400 hover:text-gray-400"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">Action</label>
                <span className={clsx(
                  'inline-block mt-1 px-2 py-1 text-sm font-medium rounded-full capitalize',
                  getActionColor(selectedLog.action)
                )}>
                  {formatAction(selectedLog.action)}
                </span>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">Timestamp</label>
                <p className="mt-1 text-sm text-white">{formatDate(selectedLog.created_at)}</p>
              </div>

              {selectedLog.actor && (
                <div>
                  <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">Actor</label>
                  <p className="mt-1 text-sm text-white">{selectedLog.actor.full_name}</p>
                  <p className="text-xs text-gray-400">{selectedLog.actor.email}</p>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">IP Address</label>
                <p className="mt-1 text-sm text-white font-mono">{selectedLog.ip_address || 'N/A'}</p>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">Status</label>
                <span className={clsx(
                  'inline-block mt-1 px-2 py-1 text-xs font-medium rounded-full',
                  selectedLog.success
                    ? 'bg-green-900/30 text-green-400'
                    : 'bg-red-900/30 text-red-400'
                )}>
                  {selectedLog.success ? 'Success' : 'Failed'}
                </span>
                {selectedLog.error_message && (
                  <p className="mt-1 text-sm text-red-400">{selectedLog.error_message}</p>
                )}
              </div>

              {selectedLog.resource_type && (
                <div>
                  <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">Resource</label>
                  <p className="mt-1 text-sm text-white">
                    {selectedLog.resource_type}: {selectedLog.resource_id}
                  </p>
                </div>
              )}

              {selectedLog.details && Object.keys(selectedLog.details).length > 0 && (
                <div>
                  <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">Details</label>
                  <pre className="mt-1 p-3 bg-gray-700/30 rounded-lg text-xs text-gray-400 overflow-x-auto">
                    {JSON.stringify(selectedLog.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
