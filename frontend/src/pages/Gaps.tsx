import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ExternalLink } from 'lucide-react'
import { accountsApi, coverageApi, Gap } from '../services/api'

const priorityStyles = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
}

export default function Gaps() {
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

  const gaps = coverage?.top_gaps ?? []

  // Group gaps by priority
  const criticalGaps = gaps.filter(g => g.priority === 'critical')
  const highGaps = gaps.filter(g => g.priority === 'high')
  const mediumGaps = gaps.filter(g => g.priority === 'medium')
  const lowGaps = gaps.filter(g => g.priority === 'low')

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!gaps.length) {
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

      {/* Gap List */}
      <div className="space-y-4">
        {gaps.map((gap) => (
          <GapCard key={gap.technique_id} gap={gap} />
        ))}
      </div>
    </div>
  )
}

function GapCard({ gap }: { gap: Gap }) {
  const mitreUrl = `https://attack.mitre.org/techniques/${gap.technique_id.replace('.', '/')}/`

  return (
    <div className={`card border-l-4 ${
      gap.priority === 'critical' ? 'border-red-500' :
      gap.priority === 'high' ? 'border-orange-500' :
      gap.priority === 'medium' ? 'border-yellow-500' :
      'border-blue-500'
    }`}>
      <div className="flex items-start justify-between">
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
          <p className="mt-2 text-sm text-gray-700">{gap.reason}</p>

          {gap.data_sources.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-medium text-gray-500 mb-1">Recommended Data Sources</p>
              <div className="flex flex-wrap gap-2">
                {gap.data_sources.map((source) => (
                  <span
                    key={source}
                    className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded"
                  >
                    {source}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
        <a
          href={mitreUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="ml-4 p-2 text-gray-400 hover:text-blue-600 transition-colors"
          title="View on MITRE ATT&CK"
        >
          <ExternalLink className="h-5 w-5" />
        </a>
      </div>
    </div>
  )
}
