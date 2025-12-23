import { useQuery } from '@tanstack/react-query'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Cloud,
  Activity,
  Zap,
  Lock
} from 'lucide-react'
import { coverageApi, scansApi, detectionsApi, scanStatusApi } from '../services/api'
import { Link } from 'react-router-dom'
import CoverageGauge from '../components/CoverageGauge'
import TacticHeatmap from '../components/TacticHeatmap'
import { useSelectedAccount } from '../hooks/useSelectedAccount'

const detectionSourceConfig: Record<string, { label: string; icon: React.ElementType; color: string; bgColor: string }> = {
  'cloudwatch_logs_insights': {
    label: 'CloudWatch Logs',
    icon: Activity,
    color: 'text-orange-600',
    bgColor: 'bg-orange-100'
  },
  'eventbridge_rule': {
    label: 'EventBridge',
    icon: Zap,
    color: 'text-purple-600',
    bgColor: 'bg-purple-100'
  },
  'guardduty_finding': {
    label: 'GuardDuty',
    icon: Shield,
    color: 'text-red-600',
    bgColor: 'bg-red-100'
  },
  'config_rule': {
    label: 'Config Rules',
    icon: CheckCircle,
    color: 'text-green-600',
    bgColor: 'bg-green-100'
  },
  'security_hub': {
    label: 'Security Hub',
    icon: Lock,
    color: 'text-blue-600',
    bgColor: 'bg-blue-100'
  }
}

export default function Dashboard() {
  const { selectedAccount, isLoading: accountsLoading, hasAccounts } = useSelectedAccount()

  const { data: coverage } = useQuery({
    queryKey: ['coverage', selectedAccount?.id],
    queryFn: () => coverageApi.get(selectedAccount!.id),
    enabled: !!selectedAccount,
  })

  // Scans query available for future use (e.g., showing latest scan info)
  useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list(),
  })

  const { data: detectionsData } = useQuery({
    queryKey: ['detections', selectedAccount?.id],
    queryFn: () => detectionsApi.list({ cloud_account_id: selectedAccount?.id, limit: 500 }),
    enabled: !!selectedAccount,
  })

  const { data: scanStatus } = useQuery({
    queryKey: ['scanStatus'],
    queryFn: () => scanStatusApi.get(),
  })

  // Calculate detection source counts
  const sourceCounts = (detectionsData?.items ?? []).reduce((acc, d) => {
    acc[d.detection_type] = (acc[d.detection_type] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  if (accountsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!hasAccounts) {
    return (
      <div className="text-center py-12">
        <Cloud className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-gray-900">No cloud accounts</h3>
        <p className="mt-1 text-sm text-gray-500">Get started by adding a cloud account.</p>
        <div className="mt-6">
          <Link to="/accounts" className="btn-primary">
            Add Cloud Account
          </Link>
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

      {/* Scan Limit Status - Only show for limited tiers */}
      {scanStatus && !scanStatus.unlimited && (
        <div className="card mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">Scan Usage</h3>
              <p className="text-sm text-gray-500">
                {scanStatus.scans_used} of {scanStatus.scans_allowed} scans used this week
              </p>
            </div>
            <div className="flex items-center space-x-4">
              {scanStatus.can_scan ? (
                <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-4 h-4 mr-1" />
                  Scan Available
                </span>
              ) : (
                <div className="text-right">
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-yellow-100 text-yellow-800">
                    <Clock className="w-4 h-4 mr-1" />
                    Limit Reached
                  </span>
                  {scanStatus.week_resets_at && (
                    <p className="text-xs text-gray-500 mt-1">
                      Resets {new Date(scanStatus.week_resets_at).toLocaleDateString()}
                    </p>
                  )}
                </div>
              )}
              <Link
                to="/settings/billing"
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                Upgrade for unlimited scans →
              </Link>
            </div>
          </div>
          {/* Progress bar */}
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className={`h-2 rounded-full ${scanStatus.can_scan ? 'bg-green-500' : 'bg-yellow-500'}`}
                style={{
                  width: `${Math.min((scanStatus.scans_used / scanStatus.scans_allowed) * 100, 100)}%`,
                }}
              />
            </div>
          </div>
        </div>
      )}

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

      {/* Detection Sources */}
      <div className="card mb-8">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Detection Sources</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Object.entries(detectionSourceConfig).map(([type, config]) => {
            const count = sourceCounts[type] || 0
            const Icon = config.icon
            return (
              <div
                key={type}
                className={`p-4 rounded-lg ${count > 0 ? config.bgColor : 'bg-gray-50'} transition-colors`}
              >
                <div className="flex items-center space-x-2">
                  <Icon className={`h-5 w-5 ${count > 0 ? config.color : 'text-gray-400'}`} />
                  <span className={`text-sm font-medium ${count > 0 ? 'text-gray-900' : 'text-gray-400'}`}>
                    {config.label}
                  </span>
                </div>
                <p className={`text-2xl font-bold mt-2 ${count > 0 ? 'text-gray-900' : 'text-gray-300'}`}>
                  {count}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  {count > 0 ? 'detections' : 'not configured'}
                </p>
              </div>
            )
          })}
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
          <Link
            to="/gaps"
            className="block mt-4 text-center text-sm text-blue-600 hover:text-blue-700"
          >
            View all gaps →
          </Link>
        </div>
      ) : null}
    </div>
  )
}
