import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ExternalLink, ChevronDown, ChevronUp, Filter, Search, Clock, Zap, Shield, Users } from 'lucide-react'
import { accountsApi, coverageApi, Gap, RecommendedStrategy } from '../services/api'
import { useState } from 'react'
import StrategyDetailModal from '../components/StrategyDetailModal'

const priorityStyles = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
}

const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 }

export default function Gaps() {
  const [search, setSearch] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')
  const [priorityFilter, setPriorityFilter] = useState('')
  const [expandedGaps, setExpandedGaps] = useState<Set<string>>(new Set())
  const [showLowPriority, setShowLowPriority] = useState(false)

  const { data: accounts } = useQuery({
    queryKey: ['accounts'],
    queryFn: accountsApi.list,
  })

  const firstAccount = accounts?.[0]

  const { data: coverage, isLoading } = useQuery({
    queryKey: ['coverage', firstAccount?.id],
    queryFn: () => coverageApi.get(firstAccount!.id),
    enabled: !!firstAccount,
  })

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
        <h3 className="mt-2 text-lg font-medium text-gray-900">No gaps identified</h3>
        <p className="mt-1 text-sm text-gray-500">
          Great job! Your coverage looks complete, or run a scan to identify gaps.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Coverage Gaps</h1>
        <p className="text-gray-600">Prioritized MITRE ATT&CK techniques lacking detection coverage</p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="stat-card border-l-4 border-red-500">
          <p className="text-2xl font-bold text-gray-900">{criticalGaps.length}</p>
          <p className="text-sm text-gray-500">Critical</p>
        </div>
        <div className="stat-card border-l-4 border-orange-500">
          <p className="text-2xl font-bold text-gray-900">{highGaps.length}</p>
          <p className="text-sm text-gray-500">High</p>
        </div>
        <div className="stat-card border-l-4 border-yellow-500">
          <p className="text-2xl font-bold text-gray-900">{mediumGaps.length}</p>
          <p className="text-sm text-gray-500">Medium</p>
        </div>
        <div className="stat-card border-l-4 border-blue-500">
          <p className="text-2xl font-bold text-gray-900">{lowGaps.length}</p>
          <p className="text-sm text-gray-500">Low</p>
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
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-gray-400" />
          <select
            value={tacticFilter}
            onChange={(e) => setTacticFilter(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Tactics</option>
            {tactics.map(tactic => (
              <option key={tactic.id} value={tactic.id}>{tactic.name}</option>
            ))}
          </select>

          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500"
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
              className="text-sm text-blue-600 hover:text-blue-700"
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
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-600">
                Show low priority ({lowGaps.length})
              </span>
            </label>
          )}
        </div>

        <div className="flex items-center space-x-2 ml-auto">
          <button
            onClick={expandAll}
            className="text-sm text-gray-600 hover:text-gray-900"
          >
            Expand all
          </button>
          <span className="text-gray-300">|</span>
          <button
            onClick={collapseAll}
            className="text-sm text-gray-600 hover:text-gray-900"
          >
            Collapse all
          </button>
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-gray-500 mb-4">
        Showing {gaps.length} {!showLowPriority && !priorityFilter && lowGaps.length > 0 ? 'actionable' : ''} gaps
        {!showLowPriority && !priorityFilter && lowGaps.length > 0 && (
          <span className="text-gray-400"> ({lowGaps.length} low priority hidden)</span>
        )}
      </p>

      {/* Gap List */}
      {gaps.length === 0 ? (
        <div className="text-center py-12 card">
          <AlertTriangle className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-gray-900">No matching gaps</h3>
          <p className="mt-1 text-sm text-gray-500">Try adjusting your filters.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {gaps.map((gap) => (
            <GapCard
              key={gap.technique_id}
              gap={gap}
              isExpanded={expandedGaps.has(gap.technique_id)}
              onToggle={() => toggleExpand(gap.technique_id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function GapCard({
  gap,
  isExpanded,
  onToggle
}: {
  gap: Gap
  isExpanded: boolean
  onToggle: () => void
}) {
  const mitreUrl = `https://attack.mitre.org/techniques/${gap.technique_id.replace('.', '/')}/`

  return (
    <div className={`card border-l-4 ${
      gap.priority === 'critical' ? 'border-red-500' :
      gap.priority === 'high' ? 'border-orange-500' :
      gap.priority === 'medium' ? 'border-yellow-500' :
      'border-blue-500'
    }`}>
      {/* Header - always visible */}
      <div
        className="flex items-start justify-between cursor-pointer"
        onClick={onToggle}
      >
        <div className="flex-1">
          <div className="flex items-center space-x-3">
            <span className={`px-2 py-1 text-xs font-medium rounded-full ${priorityStyles[gap.priority]}`}>
              {gap.priority}
            </span>
            <h3 className="font-semibold text-gray-900">
              {gap.technique_id}: {gap.technique_name}
            </h3>
          </div>
          <p className="mt-1 text-sm text-gray-500">{gap.tactic_name}</p>
        </div>
        <div className="flex items-center space-x-2">
          <a
            href={mitreUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 text-gray-400 hover:text-blue-600 transition-colors"
            title="View on MITRE ATT&CK"
            onClick={(e) => e.stopPropagation()}
          >
            <ExternalLink className="h-5 w-5" />
          </a>
          <button className="p-2 text-gray-400 hover:text-gray-600">
            {isExpanded ? (
              <ChevronUp className="h-5 w-5" />
            ) : (
              <ChevronDown className="h-5 w-5" />
            )}
          </button>
        </div>
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div className="mt-4 pt-4 border-t border-gray-100">
          {/* Threat Context - if template available */}
          {gap.has_template && (
            <div className="mb-4 grid grid-cols-2 md:grid-cols-4 gap-4">
              {gap.severity_score && (
                <div className="bg-gray-50 rounded-lg p-3">
                  <div className="flex items-center text-gray-500 text-xs mb-1">
                    <Shield className="h-3 w-3 mr-1" />
                    Severity
                  </div>
                  <p className="text-lg font-semibold text-gray-900">{gap.severity_score}/10</p>
                </div>
              )}
              {gap.total_effort_hours && (
                <div className="bg-gray-50 rounded-lg p-3">
                  <div className="flex items-center text-gray-500 text-xs mb-1">
                    <Clock className="h-3 w-3 mr-1" />
                    Total Effort
                  </div>
                  <p className="text-lg font-semibold text-gray-900">{gap.total_effort_hours}h</p>
                </div>
              )}
              {gap.threat_actors && gap.threat_actors.length > 0 && (
                <div className="bg-gray-50 rounded-lg p-3 col-span-2">
                  <div className="flex items-center text-gray-500 text-xs mb-1">
                    <Users className="h-3 w-3 mr-1" />
                    Known Threat Actors
                  </div>
                  <p className="text-sm font-medium text-gray-900">{gap.threat_actors.slice(0, 3).join(', ')}</p>
                </div>
              )}
            </div>
          )}

          {/* Reason */}
          <div className="mb-4">
            <h4 className="text-sm font-medium text-gray-700 mb-2">Why this is a gap</h4>
            <p className="text-sm text-gray-600 bg-gray-50 rounded-lg p-3">
              {gap.reason || 'No detections found covering this technique.'}
            </p>
          </div>

          {/* Business Impact */}
          {gap.business_impact && gap.business_impact.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Business Impact</h4>
              <ul className="text-sm text-gray-600 bg-red-50 rounded-lg p-3 space-y-1">
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
              <h4 className="text-sm font-medium text-gray-700 mb-2">Recommended Data Sources</h4>
              <div className="flex flex-wrap gap-2">
                {gap.data_sources.map((source) => (
                  <span
                    key={source}
                    className="px-3 py-1 text-sm bg-blue-50 text-blue-700 rounded-lg"
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
              <h4 className="text-sm font-medium text-gray-700 mb-2">
                Recommended Detection Strategies
                {gap.quick_win_strategy && (
                  <span className="ml-2 text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">
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
              <h4 className="text-sm font-medium text-gray-700 mb-2">Remediation Suggestions</h4>
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <ul className="text-sm text-green-800 space-y-2">
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
              <h4 className="text-sm font-medium text-gray-700 mb-2">Remediation Suggestions</h4>
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <ul className="text-sm text-green-800 space-y-2">
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
            <button className="btn-secondary text-sm">
              Mark as Acknowledged
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

const effortColors: Record<string, string> = {
  low: 'bg-green-100 text-green-700',
  medium: 'bg-yellow-100 text-yellow-700',
  high: 'bg-orange-100 text-orange-700',
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
      <div className={`border rounded-lg p-4 ${isQuickWin ? 'border-green-300 bg-green-50' : 'border-gray-200 bg-white'}`}>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-500">#{index}</span>
              <h5 className="font-medium text-gray-900">{strategy.name}</h5>
              {isQuickWin && (
                <span className="text-xs bg-green-200 text-green-800 px-2 py-0.5 rounded-full flex items-center">
                  <Zap className="h-3 w-3 mr-1" />
                  Quick Win
                </span>
              )}
            </div>
            <p className="text-sm text-gray-500 mt-1">
              {strategy.detection_type} via {strategy.cloud_provider === 'gcp' ? strategy.gcp_service : strategy.aws_service}
              {strategy.cloud_provider && (
                <span className={`ml-2 text-xs px-1.5 py-0.5 rounded ${strategy.cloud_provider === 'gcp' ? 'bg-blue-100 text-blue-700' : 'bg-orange-100 text-orange-700'}`}>
                  {strategy.cloud_provider.toUpperCase()}
                </span>
              )}
            </p>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs">
          <span className={`px-2 py-1 rounded ${effortColors[strategy.implementation_effort] || 'bg-gray-100 text-gray-700'}`}>
            {strategy.implementation_effort} effort
          </span>
          <span className="text-gray-500 flex items-center">
            <Clock className="h-3 w-3 mr-1" />
            {strategy.estimated_time}
          </span>
          <span className="text-gray-500">
            Coverage: {strategy.detection_coverage}
          </span>
        </div>

        {/* Available artefacts - clickable */}
        <div className="mt-3 flex flex-wrap gap-2">
          {strategy.has_query && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded hover:bg-blue-200 transition-colors cursor-pointer"
            >
              Query Available
            </button>
          )}
          {strategy.has_cloudformation && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded hover:bg-purple-200 transition-colors cursor-pointer"
            >
              CloudFormation
            </button>
          )}
          {strategy.has_terraform && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-indigo-100 text-indigo-700 px-2 py-1 rounded hover:bg-indigo-200 transition-colors cursor-pointer"
            >
              AWS Terraform
            </button>
          )}
          {strategy.has_gcp_query && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded hover:bg-blue-200 transition-colors cursor-pointer"
            >
              GCP Query
            </button>
          )}
          {strategy.has_gcp_terraform && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded hover:bg-blue-200 transition-colors cursor-pointer"
            >
              GCP Terraform
            </button>
          )}
          {hasArtefacts && (
            <button
              onClick={() => setShowModal(true)}
              className="text-xs text-blue-600 hover:text-blue-800 underline ml-2"
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
