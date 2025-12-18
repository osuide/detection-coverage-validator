import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ExternalLink, ChevronDown, ChevronUp, Filter, Search } from 'lucide-react'
import { accountsApi, coverageApi, Gap } from '../services/api'
import { useState } from 'react'

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
        Showing {gaps.length} of {allGaps.length} gaps
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
          {/* Reason */}
          <div className="mb-4">
            <h4 className="text-sm font-medium text-gray-700 mb-2">Why this is a gap</h4>
            <p className="text-sm text-gray-600 bg-gray-50 rounded-lg p-3">
              {gap.reason || 'No detections found covering this technique.'}
            </p>
          </div>

          {/* Data Sources */}
          {gap.data_sources.length > 0 && (
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

          {/* Remediation Suggestions */}
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

          {/* Actions */}
          <div className="flex items-center space-x-3">
            <a
              href={mitreUrl}
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
