import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  CheckCircle,
  ShieldAlert,
  ExternalLink,
  RotateCcw,
  Loader2,
  AlertTriangle,
  Filter,
  Search,
  Clock,
  Building2,
  User,
} from 'lucide-react'
import { gapsApi, OrgAcknowledgedGap } from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import toast from 'react-hot-toast'

const priorityStyles: Record<string, string> = {
  critical: 'bg-red-900/50 text-red-300 border border-red-700',
  high: 'bg-orange-900/50 text-orange-300 border border-orange-700',
  medium: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
  low: 'bg-blue-900/50 text-blue-300 border border-blue-700',
}

export default function AcknowledgedGapsReview() {
  const { user } = useAuth()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [accountFilter, setAccountFilter] = useState<string>('')

  const isOwnerOrAdmin = user?.role === 'owner' || user?.role === 'admin'

  const { data, isLoading, error } = useQuery({
    queryKey: ['orgAcknowledgedGaps'],
    queryFn: () => gapsApi.listOrgAcknowledged(),
    enabled: isOwnerOrAdmin,
  })

  const gaps = data?.gaps ?? []
  const byStatus = data?.by_status ?? { acknowledged: 0, risk_accepted: 0 }

  // Get unique accounts for filter
  const accounts = [...new Set(gaps.map(g => g.cloud_account_name).filter(Boolean))]

  // Apply filters
  let filteredGaps = gaps.filter(g =>
    g.technique_name?.toLowerCase().includes(search.toLowerCase()) ||
    g.technique_id.toLowerCase().includes(search.toLowerCase())
  )

  if (statusFilter) {
    filteredGaps = filteredGaps.filter(g => g.status === statusFilter)
  }

  if (accountFilter) {
    filteredGaps = filteredGaps.filter(g => g.cloud_account_name === accountFilter)
  }

  if (!isOwnerOrAdmin) {
    return (
      <div className="text-center py-12">
        <ShieldAlert className="mx-auto h-12 w-12 text-red-400" />
        <h3 className="mt-2 text-lg font-medium text-white">Access Denied</h3>
        <p className="mt-1 text-sm text-gray-400">
          Only organisation owners and admins can access this page.
        </p>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="mx-auto h-12 w-12 text-red-400" />
        <h3 className="mt-2 text-lg font-medium text-white">Failed to load acknowledged gaps</h3>
        <p className="mt-1 text-sm text-gray-400">
          {error instanceof Error ? error.message : 'An error occurred'}
        </p>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Acknowledged Gaps Review</h1>
        <p className="text-gray-400">
          Review and manage acknowledged gaps across all cloud accounts in your organisation
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-900/30 rounded-lg">
              <CheckCircle className="h-6 w-6 text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-400">Total Acknowledged</p>
              <p className="text-2xl font-bold text-white">{data?.total ?? 0}</p>
            </div>
          </div>
        </div>

        <button
          onClick={() => setStatusFilter(statusFilter === 'acknowledged' ? '' : 'acknowledged')}
          className={`bg-gray-800 rounded-lg p-6 border transition-colors text-left ${
            statusFilter === 'acknowledged' ? 'border-gray-500 bg-gray-700/50' : 'border-gray-700 hover:border-gray-600'
          }`}
        >
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gray-700/50 rounded-lg">
              <CheckCircle className="h-6 w-6 text-gray-400" />
            </div>
            <div>
              <p className="text-sm text-gray-400">Acknowledged</p>
              <p className="text-2xl font-bold text-gray-300">{byStatus.acknowledged}</p>
            </div>
          </div>
        </button>

        <button
          onClick={() => setStatusFilter(statusFilter === 'risk_accepted' ? '' : 'risk_accepted')}
          className={`bg-gray-800 rounded-lg p-6 border transition-colors text-left ${
            statusFilter === 'risk_accepted' ? 'border-purple-500 bg-purple-900/20' : 'border-gray-700 hover:border-gray-600'
          }`}
        >
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-900/30 rounded-lg">
              <ShieldAlert className="h-6 w-6 text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-400">Risk Accepted</p>
              <p className="text-2xl font-bold text-purple-400">{byStatus.risk_accepted}</p>
            </div>
          </div>
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 mb-6">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search techniques..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-400" />

          <select
            value={accountFilter}
            onChange={(e) => setAccountFilter(e.target.value)}
            className="border border-gray-600 bg-gray-800 text-gray-100 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">All Accounts</option>
            {accounts.map(account => (
              <option key={account} value={account!}>{account}</option>
            ))}
          </select>

          {(statusFilter || accountFilter || search) && (
            <button
              onClick={() => {
                setSearch('')
                setStatusFilter('')
                setAccountFilter('')
              }}
              className="text-sm text-cyan-400 hover:text-cyan-300"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-gray-400 mb-4">
        Showing {filteredGaps.length} of {gaps.length} acknowledged gaps
      </p>

      {/* Gaps List */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        {filteredGaps.length === 0 ? (
          <div className="text-center py-12">
            <CheckCircle className="mx-auto h-12 w-12 text-gray-500" />
            <h3 className="mt-2 text-lg font-medium text-white">No acknowledged gaps</h3>
            <p className="mt-1 text-sm text-gray-400">
              {gaps.length === 0
                ? 'No gaps have been acknowledged yet.'
                : 'No gaps match your current filters.'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {filteredGaps.map((gap) => (
              <AcknowledgedGapRow key={gap.id} gap={gap} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function AcknowledgedGapRow({ gap }: { gap: OrgAcknowledgedGap }) {
  const queryClient = useQueryClient()
  const mitreUrl = `https://attack.mitre.org/techniques/${gap.technique_id.replace('.', '/')}/`

  const reopenMutation = useMutation({
    mutationFn: () => gapsApi.reopenOrgGap(gap.id),
    onSuccess: () => {
      toast.success(`Gap ${gap.technique_id} reopened. It will appear in future scans.`)
      queryClient.invalidateQueries({ queryKey: ['orgAcknowledgedGaps'] })
      queryClient.invalidateQueries({ queryKey: ['coverage'] })
      queryClient.invalidateQueries({ queryKey: ['acknowledgedGaps'] })
    },
    onError: (error: Error) => {
      toast.error(`Failed to reopen gap: ${error.message}`)
    },
  })

  const isRiskAccepted = gap.status === 'risk_accepted'
  const acknowledgedDate = gap.acknowledged_at
    ? new Date(gap.acknowledged_at).toLocaleDateString('en-GB', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      })
    : null

  return (
    <div className="p-4 hover:bg-gray-700/30 transition-colors">
      <div className="flex items-start justify-between gap-4">
        {/* Left side - Gap info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            {/* Status badge */}
            {isRiskAccepted ? (
              <span className="px-2 py-1 text-xs font-medium rounded-full bg-purple-900/30 text-purple-400 border border-purple-600 flex items-center gap-1">
                <ShieldAlert className="h-3 w-3" />
                Risk Accepted
              </span>
            ) : (
              <span className="px-2 py-1 text-xs font-medium rounded-full bg-gray-700/50 text-gray-400 border border-gray-600 flex items-center gap-1">
                <CheckCircle className="h-3 w-3" />
                Acknowledged
              </span>
            )}

            {/* Priority badge */}
            <span className={`px-2 py-0.5 text-xs font-medium rounded ${priorityStyles[gap.priority] || 'bg-gray-700 text-gray-400'}`}>
              {gap.priority}
            </span>

            {/* Technique ID */}
            <span className="text-sm font-mono text-cyan-400">{gap.technique_id}</span>

            {/* Technique name */}
            <span className="font-medium text-white truncate">{gap.technique_name || 'Unknown technique'}</span>
          </div>

          {/* Tactic */}
          <p className="mt-1 text-sm text-gray-400">{gap.tactic_name || 'Unknown tactic'}</p>

          {/* Metadata row */}
          <div className="mt-2 flex items-center gap-4 text-xs text-gray-500">
            {/* Cloud account */}
            <span className="flex items-center gap-1">
              <Building2 className="h-3 w-3" />
              {gap.cloud_account_name || 'Unknown account'}
            </span>

            {/* Date */}
            {acknowledgedDate && (
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {acknowledgedDate}
              </span>
            )}

            {/* User who acknowledged */}
            {gap.acknowledged_by_name && (
              <span className="flex items-center gap-1">
                <User className="h-3 w-3" />
                {gap.acknowledged_by_name}
              </span>
            )}
          </div>

          {/* Risk acceptance reason */}
          {gap.risk_acceptance_reason && (
            <div className="mt-2 text-sm text-gray-400 bg-gray-700/50 rounded p-2 border border-gray-600">
              <span className="font-medium text-gray-300">Reason: </span>
              {gap.risk_acceptance_reason}
            </div>
          )}

          {/* Remediation notes */}
          {gap.remediation_notes && !gap.risk_acceptance_reason && (
            <div className="mt-2 text-sm text-gray-400 bg-gray-700/50 rounded p-2 border border-gray-600">
              <span className="font-medium text-gray-300">Notes: </span>
              {gap.remediation_notes}
            </div>
          )}
        </div>

        {/* Right side - Actions */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <a
            href={mitreUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 text-gray-400 hover:text-cyan-400 transition-colors rounded-lg hover:bg-gray-700/50"
            title="View on MITRE ATT&CK"
          >
            <ExternalLink className="h-4 w-4" />
          </a>

          <button
            onClick={() => reopenMutation.mutate()}
            disabled={reopenMutation.isPending}
            className="btn-secondary text-sm inline-flex items-center disabled:opacity-50 disabled:cursor-not-allowed"
            title="Reopen this gap"
          >
            {reopenMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                Reopening...
              </>
            ) : (
              <>
                <RotateCcw className="h-4 w-4 mr-1" />
                Reopen
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
