import { useQuery } from '@tanstack/react-query'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Cloud,
  Activity
} from 'lucide-react'
import { accountsApi, coverageApi, scansApi, CloudAccount } from '../services/api'
import CoverageGauge from '../components/CoverageGauge'
import TacticHeatmap from '../components/TacticHeatmap'

export default function Dashboard() {
  const { data: accounts, isLoading: accountsLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn: accountsApi.list,
  })

  const firstAccount = accounts?.[0]

  const { data: coverage, isLoading: coverageLoading } = useQuery({
    queryKey: ['coverage', firstAccount?.id],
    queryFn: () => coverageApi.get(firstAccount!.id),
    enabled: !!firstAccount,
  })

  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list(),
  })

  const latestScan = scans?.[0]

  if (accountsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!accounts?.length) {
    return (
      <div className="text-center py-12">
        <Cloud className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-gray-900">No cloud accounts</h3>
        <p className="mt-1 text-sm text-gray-500">Get started by adding a cloud account.</p>
        <div className="mt-6">
          <a href="/accounts" className="btn-primary">
            Add Cloud Account
          </a>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600">MITRE ATT&CK coverage overview</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Covered</p>
              <p className="text-2xl font-bold text-gray-900">
                {coverage?.covered_techniques ?? '-'}
              </p>
            </div>
          </div>
        </div>

        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Clock className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Partial</p>
              <p className="text-2xl font-bold text-gray-900">
                {coverage?.partial_techniques ?? '-'}
              </p>
            </div>
          </div>
        </div>

        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Gaps</p>
              <p className="text-2xl font-bold text-gray-900">
                {coverage?.uncovered_techniques ?? '-'}
              </p>
            </div>
          </div>
        </div>

        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Shield className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Detections</p>
              <p className="text-2xl font-bold text-gray-900">
                {coverage?.total_detections ?? '-'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Coverage and Heatmap */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Overall Coverage</h3>
          {coverage ? (
            <CoverageGauge
              percent={coverage.coverage_percent}
              confidence={coverage.average_confidence}
            />
          ) : (
            <div className="text-center py-8 text-gray-500">
              Run a scan to see coverage
            </div>
          )}
        </div>

        <div className="card lg:col-span-2">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Tactic Coverage</h3>
          {coverage?.tactic_coverage?.length ? (
            <TacticHeatmap tactics={coverage.tactic_coverage} />
          ) : (
            <div className="text-center py-8 text-gray-500">
              No coverage data available
            </div>
          )}
        </div>
      </div>

      {/* Top Gaps */}
      {coverage?.top_gaps?.length ? (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Coverage Gaps</h3>
          <div className="space-y-3">
            {coverage.top_gaps.slice(0, 5).map((gap) => (
              <div
                key={gap.technique_id}
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
              >
                <div>
                  <p className="font-medium text-gray-900">
                    {gap.technique_id}: {gap.technique_name}
                  </p>
                  <p className="text-sm text-gray-500">{gap.tactic_name}</p>
                </div>
                <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                  gap.priority === 'critical' ? 'bg-red-100 text-red-800' :
                  gap.priority === 'high' ? 'bg-orange-100 text-orange-800' :
                  gap.priority === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-blue-100 text-blue-800'
                }`}>
                  {gap.priority}
                </span>
              </div>
            ))}
          </div>
          <a
            href="/gaps"
            className="block mt-4 text-center text-sm text-blue-600 hover:text-blue-700"
          >
            View all gaps →
          </a>
        </div>
      ) : null}
    </div>
  )
}
