import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ExternalLink, ChevronDown, ChevronRight, Filter, Search, Clock, Zap, Shield, Users, Check, Loader2, RotateCcw, CheckCircle, ShieldAlert } from 'lucide-react'
import { coverageApi, gapsApi, Gap, RecommendedStrategy, AcknowledgedGap } from '../services/api'
import { useState } from 'react'
import StrategyDetailModal from '../components/StrategyDetailModal'
import toast from 'react-hot-toast'
import { useSelectedAccount } from '../hooks/useSelectedAccount'

// Priority styles matching Compliance page
const priorityStyles = {
  critical: 'bg-red-900/50 text-red-300 border border-red-700',
  high: 'bg-orange-900/50 text-orange-300 border border-orange-700',
  medium: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
  low: 'bg-blue-900/50 text-blue-300 border border-blue-700',
}

const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 }

export default function Gaps() {
  const [search, setSearch] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')
  const [priorityFilter, setPriorityFilter] = useState('')
  const [expandedGaps, setExpandedGaps] = useState<Set<string>>(new Set())
  const [showLowPriority, setShowLowPriority] = useState(false)
  const [showAcknowledged, setShowAcknowledged] = useState(false)

  const { selectedAccount } = useSelectedAccount()

  const { data: coverage, isLoading } = useQuery({
    queryKey: ['coverage', selectedAccount?.id],
    queryFn: () => coverageApi.get(selectedAccount!.id),
    enabled: !!selectedAccount,
  })

  // Fetch acknowledged gaps (both acknowledged and risk_accepted)
  const { data: acknowledgedGapsData } = useQuery({
    queryKey: ['acknowledgedGaps', selectedAccount?.id],
    queryFn: async () => {
      if (!selectedAccount?.id) return { gaps: [], total: 0 }
      const [acknowledged, riskAccepted] = await Promise.all([
        gapsApi.list(selectedAccount.id, 'acknowledged'),
        gapsApi.list(selectedAccount.id, 'risk_accepted'),
      ])
      return {
        gaps: [...acknowledged.gaps, ...riskAccepted.gaps],
        total: acknowledged.total + riskAccepted.total,
      }
    },
    enabled: !!selectedAccount?.id,
  })

  const acknowledgedGaps = acknowledgedGapsData?.gaps ?? []
  const acknowledgedCount = acknowledgedGapsData?.total ?? 0

  const allGaps = coverage?.top_gaps ?? []

  // Apply filters
  let gaps = allGaps.filter(g =>
    g.technique_name.toLowerCase().includes(search.toLowerCase()) ||
    g.technique_id.toLowerCase().includes(search.toLowerCase())
  )

  // Hide low priority by default unless explicitly shown or filtered
  if (!showLowPriority && !priorityFilter) {
    gaps = gaps.filter(g => g.priority !== 'low')
  }

  if (tacticFilter) {
    gaps = gaps.filter(g => g.tactic_id === tacticFilter)
  }

  if (priorityFilter) {
    gaps = gaps.filter(g => g.priority === priorityFilter)
  }

  // Sort by priority
  gaps.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority])

  // Get unique tactics for filter
  const tactics = [...new Set(allGaps.map(g => ({ id: g.tactic_id, name: g.tactic_name })))]
    .filter((v, i, a) => a.findIndex(t => t.id === v.id) === i)

  // Group gaps by priority
  const criticalGaps = allGaps.filter(g => g.priority === 'critical')
  const highGaps = allGaps.filter(g => g.priority === 'high')
  const mediumGaps = allGaps.filter(g => g.priority === 'medium')
  const lowGaps = allGaps.filter(g => g.priority === 'low')

  const toggleExpand = (techniqueId: string) => {
    setExpandedGaps(prev => {
      const newSet = new Set(prev)
      if (newSet.has(techniqueId)) {
        newSet.delete(techniqueId)
      } else {
        newSet.add(techniqueId)
      }
      return newSet
    })
  }

  const expandAll = () => {
    setExpandedGaps(new Set(gaps.map(g => g.technique_id)))
  }

  const collapseAll = () => {
    setExpandedGaps(new Set())
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!allGaps.length) {
    return (
      <div className="text-center py-12 card">
        <AlertTriangle className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-white">No gaps identified</h3>
        <p className="mt-1 text-sm text-gray-400">
          Great job! Your coverage looks complete, or run a scan to identify gaps.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Coverage Gaps</h1>
        <p className="text-gray-400">Prioritized MITRE ATT&CK techniques lacking detection coverage</p>
      </div>

      {/* Summary - matching Compliance page style */}
      <div className="bg-gray-800 rounded-lg p-6 mb-8">
        <h3 className="text-lg font-medium text-white mb-4">Gap Summary</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <button
            onClick={() => setPriorityFilter('critical')}
            className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
          >
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span className="text-sm text-gray-400 group-hover:text-gray-300">Critical</span>
            </div>
            <div className="text-2xl font-bold text-red-400">{criticalGaps.length}</div>
          </button>
          <button
            onClick={() => setPriorityFilter('high')}
            className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
          >
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              <span className="text-sm text-gray-400 group-hover:text-gray-300">High</span>
            </div>
            <div className="text-2xl font-bold text-orange-400">{highGaps.length}</div>
          </button>
          <button
            onClick={() => setPriorityFilter('medium')}
            className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
          >
            <div className="flex items-center gap-2 mb-2">
              <Clock className="w-4 h-4 text-yellow-400" />
              <span className="text-sm text-gray-400 group-hover:text-gray-300">Medium</span>
            </div>
            <div className="text-2xl font-bold text-yellow-400">{mediumGaps.length}</div>
          </button>
          <button
            onClick={() => setPriorityFilter('low')}
            className="bg-gray-700/50 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors cursor-pointer group"
          >
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-blue-400" />
              <span className="text-sm text-gray-400 group-hover:text-gray-300">Low</span>
            </div>
            <div className="text-2xl font-bold text-blue-400">{lowGaps.length}</div>
          </button>
        </div>
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
            className="w-full pl-10 pr-4 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-gray-400" />
          <select
            value={tacticFilter}
            onChange={(e) => setTacticFilter(e.target.value)}
            className="border border-gray-600 bg-gray-800 text-gray-100 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Tactics</option>
            {tactics.map(tactic => (
              <option key={tactic.id} value={tactic.id}>{tactic.name}</option>
            ))}
          </select>

          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="border border-gray-600 bg-gray-800 text-gray-100 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Priorities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {(tacticFilter || priorityFilter || search) && (
            <button
              onClick={() => {
                setSearch('')
                setTacticFilter('')
                setPriorityFilter('')
              }}
              className="text-sm text-blue-400 hover:text-blue-300"
            >
              Clear filters
            </button>
          )}

          {/* Low priority toggle */}
          {!priorityFilter && lowGaps.length > 0 && (
            <label className="flex items-center space-x-2 cursor-pointer ml-2">
              <input
                type="checkbox"
                checked={showLowPriority}
                onChange={(e) => setShowLowPriority(e.target.checked)}
                className="rounded-sm border-gray-600 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-400">
                Show low priority ({lowGaps.length})
              </span>
            </label>
          )}

          {/* Acknowledged gaps toggle */}
          {acknowledgedCount > 0 && (
            <label className="flex items-center space-x-2 cursor-pointer ml-2">
              <input
                type="checkbox"
                checked={showAcknowledged}
                onChange={(e) => setShowAcknowledged(e.target.checked)}
                className="rounded-sm border-gray-600 text-purple-600 focus:ring-purple-500"
              />
              <span className="text-sm text-gray-400">
                Show acknowledged ({acknowledgedCount})
              </span>
            </label>
          )}
        </div>

        <div className="flex items-center space-x-2 ml-auto">
          <button
            onClick={expandAll}
            className="text-sm text-gray-400 hover:text-white"
          >
            Expand all
          </button>
          <span className="text-gray-300">|</span>
          <button
            onClick={collapseAll}
            className="text-sm text-gray-400 hover:text-white"
          >
            Collapse all
          </button>
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-gray-400 mb-4">
        Showing {gaps.length} {!showLowPriority && !priorityFilter && lowGaps.length > 0 ? 'actionable' : ''} gaps
        {!showLowPriority && !priorityFilter && lowGaps.length > 0 && (
          <span className="text-gray-400"> ({lowGaps.length} low priority hidden)</span>
        )}
      </p>

      {/* Gap List - wrapped in card like Compliance */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium text-white">
            Actionable Gaps
            <span className="text-sm font-normal text-gray-400 ml-2">
              ({gaps.length} techniques)
            </span>
          </h3>
        </div>

        {gaps.length === 0 ? (
          <div className="text-center py-8">
            <AlertTriangle className="mx-auto h-8 w-8 text-gray-500 mb-2" />
            <p className="text-gray-400">No matching gaps found.</p>
            <button
              onClick={() => {
                setSearch('')
                setTacticFilter('')
                setPriorityFilter('')
              }}
              className="mt-2 text-blue-400 hover:text-blue-300 text-sm"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {gaps.map((gap) => (
              <GapCard
                key={gap.technique_id}
                gap={gap}
                isExpanded={expandedGaps.has(gap.technique_id)}
                onToggle={() => toggleExpand(gap.technique_id)}
                accountId={selectedAccount?.id}
              />
            ))}
          </div>
        )}
      </div>

      {/* Acknowledged Gaps Section */}
      {showAcknowledged && acknowledgedGaps.length > 0 && (
        <div className="mt-8">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
            <CheckCircle className="h-5 w-5 text-purple-500 mr-2" />
            Acknowledged Gaps
          </h2>
          <p className="text-sm text-gray-400 mb-4">
            These gaps have been acknowledged or risk-accepted. They will not appear in future scans unless reopened.
          </p>
          <div className="space-y-3">
            {acknowledgedGaps.map((gap) => (
              <AcknowledgedGapCard
                key={gap.id}
                gap={gap}
                accountId={selectedAccount?.id}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function GapCard({
  gap,
  isExpanded,
  onToggle,
  accountId
}: {
  gap: Gap
  isExpanded: boolean
  onToggle: () => void
  accountId: string | undefined
}) {
  const queryClient = useQueryClient()
  const mitreUrl = `https://attack.mitre.org/techniques/${gap.technique_id.replace('.', '/')}/`
  const [isAcknowledged, setIsAcknowledged] = useState(false)

  const acknowledgeMutation = useMutation({
    mutationFn: () => {
      if (!accountId) throw new Error('No account selected')
      return gapsApi.acknowledge(gap.technique_id, accountId)
    },
    onSuccess: () => {
      // Show acknowledged state immediately
      setIsAcknowledged(true)
      toast.success(`Gap ${gap.technique_id} acknowledged. It will not appear in future scans.`)
      // Delay the query invalidation slightly so user sees the "Acknowledged" state
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['coverage'] })
        queryClient.invalidateQueries({ queryKey: ['acknowledgedGaps'] })
      }, 1500)
    },
    onError: (error: Error) => {
      toast.error(`Failed to acknowledge gap: ${error.message}`)
    }
  })

  return (
    <div className="bg-gray-700/30 rounded-lg p-4 hover:bg-gray-700/50 transition-colors">
      {/* Header - always visible */}
      <div
        className="flex items-start justify-between cursor-pointer"
        onClick={onToggle}
      >
        <div className="flex-1">
          <div className="flex items-center gap-3">
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-gray-400 shrink-0" />
            ) : (
              <ChevronRight className="w-4 h-4 text-gray-400 shrink-0" />
            )}
            <span className={`px-2 py-0.5 text-xs font-medium rounded-sm ${priorityStyles[gap.priority]}`}>
              {gap.priority}
            </span>
            <span className="text-sm font-mono text-blue-400">{gap.technique_id}</span>
            <span className="font-medium text-white">{gap.technique_name}</span>
          </div>
          <p className="mt-1 ml-7 text-sm text-gray-400">{gap.tactic_name}</p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={mitreUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="p-1.5 text-gray-400 hover:text-blue-400 transition-colors"
            title="View on MITRE ATT&CK"
            onClick={(e) => e.stopPropagation()}
          >
            <ExternalLink className="h-4 w-4" />
          </a>
        </div>
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div className="mt-4 pt-4 border-t border-gray-700">
          {/* Threat Context - if template available */}
          {gap.has_template && (
            <div className="mb-4 grid grid-cols-2 md:grid-cols-4 gap-4">
              {gap.severity_score && (
                <div className="bg-gray-700/30 rounded-lg p-3">
                  <div className="flex items-center text-gray-400 text-xs mb-1">
                    <Shield className="h-3 w-3 mr-1" />
                    Severity
                  </div>
                  <p className="text-lg font-semibold text-white">{gap.severity_score}/10</p>
                </div>
              )}
              {gap.total_effort_hours && (
                <div className="bg-gray-700/30 rounded-lg p-3">
                  <div className="flex items-center text-gray-400 text-xs mb-1">
                    <Clock className="h-3 w-3 mr-1" />
                    Total Effort
                  </div>
                  <p className="text-lg font-semibold text-white">{gap.total_effort_hours}h</p>
                </div>
              )}
              {gap.threat_actors && gap.threat_actors.length > 0 && (
                <div className="bg-gray-700/30 rounded-lg p-3 col-span-2">
                  <div className="flex items-center text-gray-400 text-xs mb-1">
                    <Users className="h-3 w-3 mr-1" />
                    Known Threat Actors
                  </div>
                  <p className="text-sm font-medium text-white">{gap.threat_actors.slice(0, 3).join(', ')}</p>
                </div>
              )}
            </div>
          )}

          {/* Reason */}
          <div className="mb-4">
            <h4 className="text-sm font-medium text-gray-400 mb-2">Why this is a gap</h4>
            <p className="text-sm text-gray-400 bg-gray-700/30 rounded-lg p-3">
              {gap.reason || 'No detections found covering this technique.'}
            </p>
          </div>

          {/* Business Impact */}
          {gap.business_impact && gap.business_impact.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Business Impact</h4>
              <ul className="text-sm text-gray-400 bg-red-900/30 rounded-lg p-3 space-y-1">
                {gap.business_impact.map((impact, idx) => (
                  <li key={idx} className="flex items-start">
                    <span className="text-red-500 mr-2">•</span>
                    {impact}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Data Sources */}
          {gap.data_sources && gap.data_sources.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Recommended Data Sources</h4>
              <div className="flex flex-wrap gap-2">
                {gap.data_sources.map((source) => (
                  <span
                    key={source}
                    className="px-3 py-1 text-sm bg-blue-900/30 text-blue-400 rounded-lg"
                  >
                    {source}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Strategies from Template */}
          {gap.recommended_strategies && gap.recommended_strategies.length > 0 ? (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">
                Recommended Detection Strategies
                {gap.quick_win_strategy && (
                  <span className="ml-2 text-xs bg-green-900/30 text-green-400 px-2 py-0.5 rounded-full">
                    <Zap className="h-3 w-3 inline mr-1" />
                    Quick win available
                  </span>
                )}
              </h4>
              <div className="space-y-3">
                {gap.recommended_strategies.map((strategy, idx) => (
                  <StrategyCard
                    key={strategy.strategy_id}
                    techniqueId={gap.technique_id}
                    strategy={strategy}
                    isQuickWin={strategy.strategy_id === gap.quick_win_strategy}
                    index={idx + 1}
                  />
                ))}
              </div>
            </div>
          ) : gap.recommended_detections && gap.recommended_detections.length > 0 ? (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Remediation Suggestions</h4>
              <div className="bg-green-900/30 border border-green-600 rounded-lg p-4">
                <ul className="text-sm text-green-400 space-y-2">
                  {gap.recommended_detections.map((detection, idx) => (
                    <li key={idx} className="flex items-start">
                      <span className="mr-2">{idx + 1}.</span>
                      <span>{detection}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Remediation Suggestions</h4>
              <div className="bg-green-900/30 border border-green-600 rounded-lg p-4">
                <ul className="text-sm text-green-400 space-y-2">
                  <li className="flex items-start">
                    <span className="mr-2">1.</span>
                    <span>Create EventBridge rule monitoring relevant CloudTrail events</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">2.</span>
                    <span>Set up CloudWatch Logs Insights query for log-based detection</span>
                  </li>
                  <li className="flex items-start">
                    <span className="mr-2">3.</span>
                    <span>Consider enabling AWS GuardDuty for managed threat detection</span>
                  </li>
                </ul>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center space-x-3">
            <a
              href={gap.mitre_url || mitreUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary text-sm"
            >
              View MITRE Details
            </a>
            <button
              onClick={(e) => {
                e.stopPropagation()
                if (!isAcknowledged) {
                  acknowledgeMutation.mutate()
                }
              }}
              disabled={acknowledgeMutation.isPending || !accountId || isAcknowledged}
              className={`text-sm inline-flex items-center transition-all duration-300 ${
                isAcknowledged
                  ? 'bg-green-600/20 text-green-400 border border-green-600 px-3 py-1.5 rounded-lg cursor-default'
                  : 'btn-secondary disabled:opacity-50 disabled:cursor-not-allowed'
              }`}
            >
              {acknowledgeMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  Acknowledging...
                </>
              ) : isAcknowledged ? (
                <>
                  <CheckCircle className="h-4 w-4 mr-1" />
                  Acknowledged
                </>
              ) : (
                <>
                  <Check className="h-4 w-4 mr-1" />
                  Mark as Acknowledged
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// Acknowledged gap card with reopen functionality
function AcknowledgedGapCard({
  gap,
  accountId
}: {
  gap: AcknowledgedGap
  accountId: string | undefined
}) {
  const queryClient = useQueryClient()
  const mitreUrl = `https://attack.mitre.org/techniques/${gap.technique_id.replace('.', '/')}/`

  const reopenMutation = useMutation({
    mutationFn: () => {
      if (!accountId) throw new Error('No account selected')
      return gapsApi.reopen(gap.technique_id, accountId)
    },
    onSuccess: () => {
      toast.success(`Gap ${gap.technique_id} reopened. It will appear in future scans.`)
      // Invalidate both queries to refresh
      queryClient.invalidateQueries({ queryKey: ['coverage'] })
      queryClient.invalidateQueries({ queryKey: ['acknowledgedGaps'] })
    },
    onError: (error: Error) => {
      toast.error(`Failed to reopen gap: ${error.message}`)
    }
  })

  const isRiskAccepted = gap.status === 'risk_accepted'

  return (
    <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center space-x-3">
            {isRiskAccepted ? (
              <span className="px-2 py-1 text-xs font-medium rounded-full bg-purple-900/30 text-purple-400 border border-purple-600 flex items-center">
                <ShieldAlert className="h-3 w-3 mr-1" />
                Risk Accepted
              </span>
            ) : (
              <span className="px-2 py-1 text-xs font-medium rounded-full bg-gray-700/30 text-gray-400 border border-gray-600 flex items-center">
                <CheckCircle className="h-3 w-3 mr-1" />
                Acknowledged
              </span>
            )}
            <h3 className="font-semibold text-gray-400">
              {gap.technique_id}: {gap.technique_name || 'Unknown technique'}
            </h3>
          </div>
          <p className="mt-1 text-sm text-gray-400">{gap.tactic_name || 'Unknown tactic'}</p>

          {/* Show reason if available */}
          {(gap.risk_acceptance_reason || gap.remediation_notes) && (
            <div className="mt-2 text-sm text-gray-400 bg-gray-700 rounded-sm p-2 border border-gray-700">
              <span className="font-medium">Note: </span>
              {gap.risk_acceptance_reason || gap.remediation_notes}
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2">
          <a
            href={mitreUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 text-gray-400 hover:text-blue-400 transition-colors"
            title="View on MITRE ATT&CK"
          >
            <ExternalLink className="h-5 w-5" />
          </a>
          <button
            onClick={() => reopenMutation.mutate()}
            disabled={reopenMutation.isPending || !accountId}
            className="btn-secondary text-sm inline-flex items-center disabled:opacity-50 disabled:cursor-not-allowed"
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

const effortColors: Record<string, string> = {
  low: 'bg-green-900/30 text-green-400',
  medium: 'bg-yellow-900/30 text-yellow-400',
  high: 'bg-orange-900/30 text-orange-400',
}

function StrategyCard({
  techniqueId,
  strategy,
  isQuickWin,
  index
}: {
  techniqueId: string
  strategy: RecommendedStrategy
  isQuickWin: boolean
  index: number
}) {
  const [showModal, setShowModal] = useState(false)

  const hasArtefacts = strategy.has_query || strategy.has_cloudformation || strategy.has_terraform || strategy.has_gcp_query || strategy.has_gcp_terraform

  return (
    <>
      <div className={`border rounded-lg p-4 ${isQuickWin ? 'border-green-600 bg-green-900/30' : 'border-gray-700 bg-gray-700/30'}`}>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-400">#{index}</span>
              <h5 className="font-medium text-white">{strategy.name}</h5>
              {isQuickWin && (
                <span className="text-xs bg-green-900/30 text-green-400 px-2 py-0.5 rounded-full flex items-center">
                  <Zap className="h-3 w-3 mr-1" />
                  Quick Win
                </span>
              )}
            </div>
            <p className="text-sm text-gray-400 mt-1">
              {strategy.detection_type} via {strategy.cloud_provider === 'gcp' ? strategy.gcp_service : strategy.aws_service}
              {strategy.cloud_provider && (
                <span className={`ml-2 text-xs px-1.5 py-0.5 rounded-sm ${strategy.cloud_provider === 'gcp' ? 'bg-blue-900/30 text-blue-400' : 'bg-orange-900/30 text-orange-400'}`}>
                  {strategy.cloud_provider.toUpperCase()}
                </span>
              )}
            </p>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs">
          <span className={`px-2 py-1 rounded-sm ${effortColors[strategy.implementation_effort] || 'bg-gray-700/30 text-gray-400'}`}>
            {strategy.implementation_effort} effort
          </span>
          <span className="text-gray-400 flex items-center">
            <Clock className="h-3 w-3 mr-1" />
            {strategy.estimated_time}
          </span>
          <span className="text-gray-400">
            Coverage: {strategy.detection_coverage}
          </span>
        </div>

        {/* Available artefacts - clickable */}
        <div className="mt-3 flex flex-wrap gap-2">
          {strategy.has_query && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-blue-900/30 text-blue-400 px-2 py-1 rounded-sm hover:bg-blue-900/50 transition-colors cursor-pointer"
            >
              Query Available
            </button>
          )}
          {strategy.has_cloudformation && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-purple-900/30 text-purple-400 px-2 py-1 rounded-sm hover:bg-purple-900/50 transition-colors cursor-pointer"
            >
              CloudFormation
            </button>
          )}
          {strategy.has_terraform && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-indigo-900/30 text-indigo-400 px-2 py-1 rounded-sm hover:bg-indigo-900/50 transition-colors cursor-pointer"
            >
              AWS Terraform
            </button>
          )}
          {strategy.has_gcp_query && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-blue-900/30 text-blue-400 px-2 py-1 rounded-sm hover:bg-blue-900/50 transition-colors cursor-pointer"
            >
              GCP Query
            </button>
          )}
          {strategy.has_gcp_terraform && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-blue-900/30 text-blue-400 px-2 py-1 rounded-sm hover:bg-blue-900/50 transition-colors cursor-pointer"
            >
              GCP Terraform
            </button>
          )}
          {hasArtefacts && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs text-blue-400 hover:text-blue-300 underline ml-2"
            >
              View Details
            </button>
          )}
        </div>
      </div>

      {/* Strategy Detail Modal */}
      {showModal && (
        <StrategyDetailModal
          techniqueId={techniqueId}
          strategyId={strategy.strategy_id}
          strategyName={strategy.name}
          onClose={() => setShowModal(false)}
        />
      )}
    </>
  )
}
