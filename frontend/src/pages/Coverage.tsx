import { useQuery } from '@tanstack/react-query'
import { BarChart3, RefreshCw } from 'lucide-react'
import { accountsApi, coverageApi } from '../services/api'
import TacticHeatmap from '../components/TacticHeatmap'
import CoverageGauge from '../components/CoverageGauge'

export default function Coverage() {
  const { data: accounts } = useQuery({
    queryKey: ['accounts'],
    queryFn: accountsApi.list,
  })

  const firstAccount = accounts?.[0]

  const { data: coverage, isLoading, refetch } = useQuery({
    queryKey: ['coverage', firstAccount?.id],
    queryFn: () => coverageApi.get(firstAccount!.id),
    enabled: !!firstAccount,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!coverage) {
    return (
      <div className="text-center py-12 card">
        <BarChart3 className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-gray-900">No coverage data</h3>
        <p className="mt-1 text-sm text-gray-500">
          Run a scan on your cloud accounts to calculate coverage.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">MITRE ATT&CK Coverage</h1>
          <p className="text-gray-600">
            Version {coverage.mitre_version} • Last updated {new Date(coverage.created_at).toLocaleString()}
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="btn-secondary flex items-center"
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-green-600">{coverage.covered_techniques}</p>
          <p className="text-sm text-gray-500">Covered</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-yellow-600">{coverage.partial_techniques}</p>
          <p className="text-sm text-gray-500">Partial</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-gray-400">{coverage.uncovered_techniques}</p>
          <p className="text-sm text-gray-500">Uncovered</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-blue-600">{coverage.total_techniques}</p>
          <p className="text-sm text-gray-500">Total Techniques</p>
        </div>
      </div>

      {/* Main Coverage View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-6">Overall Score</h3>
          <CoverageGauge
            percent={coverage.coverage_percent}
            confidence={coverage.average_confidence}
          />
          <div className="mt-6 grid grid-cols-2 gap-4 text-center">
            <div className="p-3 bg-gray-50 rounded-lg">
              <p className="text-xl font-bold text-gray-900">{coverage.total_detections}</p>
              <p className="text-xs text-gray-500">Total Detections</p>
            </div>
            <div className="p-3 bg-gray-50 rounded-lg">
              <p className="text-xl font-bold text-gray-900">{coverage.mapped_detections}</p>
              <p className="text-xs text-gray-500">Mapped</p>
            </div>
          </div>
        </div>

        <div className="card lg:col-span-2">
          <h3 className="text-lg font-semibold text-gray-900 mb-6">Coverage by Tactic</h3>
          <TacticHeatmap tactics={coverage.tactic_coverage} />
        </div>
      </div>

      {/* Legend */}
      <div className="mt-6 card">
        <h4 className="text-sm font-medium text-gray-700 mb-3">Coverage Legend</h4>
        <div className="flex space-x-6">
          <div className="flex items-center">
            <div className="w-4 h-4 bg-green-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Covered (≥60% confidence)</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-yellow-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Partial (40-60% confidence)</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-gray-300 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Uncovered (&lt;40% confidence)</span>
          </div>
        </div>
      </div>
    </div>
  )
}
