import { useQuery } from '@tanstack/react-query'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Cloud,
  Activity,
  Zap,
  Lock,
  Bell
} from 'lucide-react'
import { coverageApi, scansApi, detectionsApi, scanStatusApi, Detection, DetectionEffectiveness } from '../services/api'
import { Link } from 'react-router-dom'
import CoverageGauge from '../components/CoverageGauge'
import TacticHeatmap from '../components/TacticHeatmap'
import { SecurityPostureCard, SecurityPostureEmptyState } from '../components/SecurityPostureCard'
import { useSelectedAccount } from '../hooks/useSelectedAccount'

const detectionSourceConfig: Record<string, { label: string; icon: React.ElementType; color: string; bgColor: string }> = {
  'cloudwatch_logs_insights': {
    label: 'CloudWatch Logs',
    icon: Activity,
    color: 'text-orange-400',
    bgColor: 'bg-orange-900/30'
  },
  'cloudwatch_alarm': {
    label: 'CloudWatch Alarms',
    icon: Bell,
    color: 'text-amber-400',
    bgColor: 'bg-amber-900/30'
  },
  'eventbridge_rule': {
    label: 'EventBridge',
    icon: Zap,
    color: 'text-purple-400',
    bgColor: 'bg-purple-900/30'
  },
  'guardduty_finding': {
    label: 'GuardDuty',
    icon: Shield,
    color: 'text-red-400',
    bgColor: 'bg-red-900/30'
  },
  'config_rule': {
    label: 'Config Rules',
    icon: CheckCircle,
    color: 'text-green-400',
    bgColor: 'bg-green-900/30'
  },
  'security_hub': {
    label: 'Security Hub',
    icon: Lock,
    color: 'text-blue-400',
    bgColor: 'bg-blue-900/30'
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

  // Use dedicated endpoint for source counts (more efficient than fetching all detections)
  const { data: sourceCountsData } = useQuery({
    queryKey: ['detectionSourceCounts', selectedAccount?.id],
    queryFn: () => detectionsApi.getSourceCounts({ cloud_account_id: selectedAccount?.id }),
    enabled: !!selectedAccount,
  })

  const { data: scanStatus } = useQuery({
    queryKey: ['scanStatus'],
    queryFn: () => scanStatusApi.get(),
  })

  // Fetch all detections (we'll filter for Security Hub client-side)
  const { data: allDetections } = useQuery({
    queryKey: ['allDetections', selectedAccount?.id],
    queryFn: () => detectionsApi.list({
      cloud_account_id: selectedAccount?.id,
      limit: 500, // Get all detections
    }),
    enabled: !!selectedAccount,
  })

  // Extract Security Hub standards with detection effectiveness data
  const securityPostureData = (allDetections?.items ?? [])
    .filter((d: Detection) => {
      // Only Security Hub detections with effectiveness data
      if (d.detection_type !== 'security_hub') return false
      const rawConfig = d.raw_config as Record<string, unknown> | undefined
      return rawConfig?.standard_id && rawConfig?.detection_effectiveness
    })
    .map((d: Detection) => {
      const rawConfig = d.raw_config as Record<string, unknown>
      return {
        standardId: rawConfig.standard_id as string,
        standardName: rawConfig.standard_name as string,
        effectiveness: rawConfig.detection_effectiveness as DetectionEffectiveness,
        region: d.region,
      }
    })

  // Convert source counts array to object for lookup
  const sourceCounts = (sourceCountsData?.counts ?? []).reduce((acc, item) => {
    acc[item.detection_type] = item.count
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
        <Cloud className="mx-auto h-12 w-12 text-gray-500" />
        <h3 className="mt-2 text-lg font-medium text-white">No cloud accounts</h3>
        <p className="mt-1 text-sm text-gray-400">Get started by adding a cloud account.</p>
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
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400">MITRE ATT&CK coverage overview</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-green-900/30 rounded-lg">
              <CheckCircle className="h-6 w-6 text-green-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-400">Covered</p>
              <p className="text-2xl font-bold text-white">
                {coverage?.covered_techniques ?? '-'}
              </p>
            </div>
          </div>
        </div>

        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-900/30 rounded-lg">
              <Clock className="h-6 w-6 text-yellow-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-400">Partial</p>
              <p className="text-2xl font-bold text-white">
                {coverage?.partial_techniques ?? '-'}
              </p>
            </div>
          </div>
        </div>

        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-red-900/30 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-red-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-400">Gaps</p>
              <p className="text-2xl font-bold text-white">
                {coverage?.uncovered_techniques ?? '-'}
              </p>
            </div>
          </div>
        </div>

        <div className="stat-card">
          <div className="flex items-center">
            <div className="p-2 bg-blue-900/30 rounded-lg">
              <Shield className="h-6 w-6 text-blue-400" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-400">Detections</p>
              <p className="text-2xl font-bold text-white">
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
              <h3 className="text-lg font-semibold text-white">Scan Usage</h3>
              <p className="text-sm text-gray-400">
                {scanStatus.scans_used} of {scanStatus.scans_allowed} scans used this week
              </p>
            </div>
            <div className="flex items-center space-x-4">
              {scanStatus.can_scan ? (
                <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-900/30 text-green-400">
                  <CheckCircle className="w-4 h-4 mr-1" />
                  Scan Available
                </span>
              ) : (
                <div className="text-right">
                  <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-yellow-900/30 text-yellow-400">
                    <Clock className="w-4 h-4 mr-1" />
                    Limit Reached
                  </span>
                  {scanStatus.week_resets_at && (
                    <p className="text-xs text-gray-400 mt-1">
                      Resets {new Date(scanStatus.week_resets_at).toLocaleDateString()}
                    </p>
                  )}
                </div>
              )}
              <Link
                to="/settings/billing"
                className="text-sm text-blue-400 hover:text-blue-300"
              >
                Upgrade for unlimited scans →
              </Link>
            </div>
          </div>
          {/* Progress bar */}
          <div className="mt-4">
            <div className="w-full bg-gray-700 rounded-full h-2">
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
          <h3 className="text-lg font-semibold text-white mb-4">Overall Coverage</h3>
          {coverage ? (
            <CoverageGauge
              percent={coverage.coverage_percent}
              confidence={coverage.average_confidence}
            />
          ) : (
            <div className="text-center py-8 text-gray-400">
              Run a scan to see coverage
            </div>
          )}
        </div>

        <div className="card lg:col-span-2">
          <h3 className="text-lg font-semibold text-white mb-4">Tactic Coverage</h3>
          {coverage?.tactic_coverage?.length ? (
            <TacticHeatmap tactics={coverage.tactic_coverage} />
          ) : (
            <div className="text-center py-8 text-gray-400">
              No coverage data available
            </div>
          )}
        </div>
      </div>

      {/* Detection Sources */}
      <div className="card mb-8">
        <h3 className="text-lg font-semibold text-white mb-4">Detection Sources</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Object.entries(detectionSourceConfig).map(([type, config]) => {
            const count = sourceCounts[type] || 0
            const Icon = config.icon
            return (
              <div
                key={type}
                className={`p-4 rounded-lg ${count > 0 ? config.bgColor : 'bg-gray-700/30'} transition-colors`}
              >
                <div className="flex items-center space-x-2">
                  <Icon className={`h-5 w-5 ${count > 0 ? config.color : 'text-gray-400'}`} />
                  <span className={`text-sm font-medium ${count > 0 ? 'text-white' : 'text-gray-400'}`}>
                    {config.label}
                  </span>
                </div>
                <p className={`text-2xl font-bold mt-2 ${count > 0 ? 'text-white' : 'text-gray-500'}`}>
                  {count}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  {count > 0 ? 'detections' : 'not configured'}
                </p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Security Posture - Detection Effectiveness from Security Hub */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Security Posture</h3>
            <p className="text-sm text-gray-400">Detection effectiveness from Security Hub standards</p>
          </div>
          {securityPostureData.length > 0 && (
            <Link
              to="/compliance"
              className="text-sm text-blue-400 hover:text-blue-300"
            >
              View Details →
            </Link>
          )}
        </div>
        {securityPostureData.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {securityPostureData.map((data) => (
              <SecurityPostureCard
                key={data.standardId}
                standardId={data.standardId}
                standardName={data.standardName}
                effectiveness={data.effectiveness}
                region={data.region}
              />
            ))}
          </div>
        ) : (
          <SecurityPostureEmptyState />
        )}
      </div>

      {/* Top Gaps */}
      {coverage?.top_gaps?.length ? (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Top Coverage Gaps</h3>
          <div className="space-y-3">
            {coverage.top_gaps.slice(0, 5).map((gap) => (
              <div
                key={gap.technique_id}
                className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg"
              >
                <div>
                  <p className="font-medium text-white">
                    {gap.technique_id}: {gap.technique_name}
                  </p>
                  <p className="text-sm text-gray-400">{gap.tactic_name}</p>
                </div>
                <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                  gap.priority === 'critical' ? 'bg-red-900/30 text-red-400' :
                  gap.priority === 'high' ? 'bg-orange-900/30 text-orange-400' :
                  gap.priority === 'medium' ? 'bg-yellow-900/30 text-yellow-400' :
                  'bg-blue-900/30 text-blue-400'
                }`}>
                  {gap.priority}
                </span>
              </div>
            ))}
          </div>
          <Link
            to="/gaps"
            className="block mt-4 text-center text-sm text-blue-400 hover:text-blue-300"
          >
            View all gaps →
          </Link>
        </div>
      ) : null}
    </div>
  )
}
