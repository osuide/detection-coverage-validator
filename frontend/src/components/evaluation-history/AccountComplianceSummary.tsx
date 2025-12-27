/**
 * Account Compliance Summary Component.
 *
 * Displays an overview card with key compliance metrics,
 * including health percentage, detection breakdown, and trends.
 */

import { Shield, TrendingUp, TrendingDown, Minus, Activity, AlertTriangle, CheckCircle } from 'lucide-react'
import { AccountEvaluationSummaryResponse } from '../../services/api'

interface AccountComplianceSummaryProps {
  data: AccountEvaluationSummaryResponse | null
  isLoading?: boolean
}

function CircularProgress({ percentage, size = 120, strokeWidth = 8 }: { percentage: number; size?: number; strokeWidth?: number }) {
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const offset = circumference - (percentage / 100) * circumference

  // Colour based on percentage
  let strokeColour = '#ef4444' // red
  if (percentage >= 80) {
    strokeColour = '#22c55e' // green
  } else if (percentage >= 60) {
    strokeColour = '#eab308' // yellow
  }

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#374151"
          strokeWidth={strokeWidth}
          fill="none"
        />
        {/* Progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={strokeColour}
          strokeWidth={strokeWidth}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-500"
        />
      </svg>
      {/* Centre text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-white">{percentage.toFixed(1)}%</span>
        <span className="text-xs text-gray-400">Health</span>
      </div>
    </div>
  )
}

function TrendIndicator({ trend, change }: { trend: string; change: number }) {
  const config = {
    improving: {
      icon: TrendingUp,
      colour: 'text-green-400',
      label: 'Improving',
    },
    declining: {
      icon: TrendingDown,
      colour: 'text-red-400',
      label: 'Declining',
    },
    stable: {
      icon: Minus,
      colour: 'text-gray-400',
      label: 'Stable',
    },
  }

  const { icon: Icon, colour, label } = config[trend as keyof typeof config] || config.stable

  return (
    <div className="flex items-center gap-2">
      <Icon className={`h-4 w-4 ${colour}`} />
      <span className={`text-sm ${colour}`}>{label}</span>
      {change !== 0 && (
        <span className={`text-xs ${colour}`}>
          ({change > 0 ? '+' : ''}{change.toFixed(1)}%)
        </span>
      )}
    </div>
  )
}

function StatCard({
  icon: Icon,
  label,
  value,
  colour = 'text-white',
  bgColour = 'bg-gray-700/50',
}: {
  icon: React.ElementType
  label: string
  value: string | number
  colour?: string
  bgColour?: string
}) {
  return (
    <div className={`rounded-lg p-4 ${bgColour}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className={`h-4 w-4 ${colour}`} />
        <span className="text-xs text-gray-400">{label}</span>
      </div>
      <p className={`text-2xl font-bold ${colour}`}>{value}</p>
    </div>
  )
}

export function AccountComplianceSummary({ data, isLoading }: AccountComplianceSummaryProps) {
  if (isLoading) {
    return (
      <div className="card p-6">
        <div className="animate-pulse">
          <div className="flex items-center gap-2 mb-6">
            <div className="h-6 w-6 bg-gray-700 rounded" />
            <div className="h-6 bg-gray-700 rounded w-48" />
          </div>
          <div className="flex items-center gap-8">
            <div className="w-32 h-32 bg-gray-700 rounded-full" />
            <div className="flex-1 grid grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-20 bg-gray-700/50 rounded-lg" />
              ))}
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="card p-6">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="h-5 w-5 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">Compliance Overview</h3>
        </div>
        <div className="flex items-center justify-center h-32 text-gray-400">
          <p>No data available. Run a scan to view compliance metrics.</p>
        </div>
      </div>
    )
  }

  const { summary, trends, by_detection_type } = data

  return (
    <div className="card p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">Compliance Overview</h3>
        </div>
        <TrendIndicator trend={trends.trend} change={trends.health_change_percent} />
      </div>

      {/* Main Content */}
      <div className="flex items-center gap-8 mb-6">
        {/* Circular Progress */}
        <CircularProgress percentage={summary.health_percentage} />

        {/* Stats Grid */}
        <div className="flex-1 grid grid-cols-3 gap-4">
          <StatCard
            icon={Activity}
            label="Total Detections"
            value={summary.total_detections}
          />
          <StatCard
            icon={CheckCircle}
            label="Healthy"
            value={summary.health_status_breakdown.healthy}
            colour="text-green-400"
            bgColour="bg-green-900/20"
          />
          <StatCard
            icon={AlertTriangle}
            label="Unhealthy"
            value={summary.health_status_breakdown.unhealthy}
            colour="text-red-400"
            bgColour="bg-red-900/20"
          />
        </div>
      </div>

      {/* Detection Type Breakdown */}
      {by_detection_type.length > 0 && (
        <div className="border-t border-gray-700 pt-4">
          <h4 className="text-sm font-medium text-gray-400 mb-3">By Detection Type</h4>
          <div className="space-y-2">
            {by_detection_type.map((dtype) => {
              const healthPct = dtype.total > 0
                ? (dtype.healthy_count / dtype.total) * 100
                : 0

              return (
                <div key={dtype.detection_type} className="flex items-center gap-4">
                  <span className="text-sm text-gray-300 w-40 truncate" title={dtype.detection_type}>
                    {dtype.detection_type.replace(/_/g, ' ')}
                  </span>
                  <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all ${
                        healthPct >= 80
                          ? 'bg-green-500'
                          : healthPct >= 60
                          ? 'bg-yellow-500'
                          : 'bg-red-500'
                      }`}
                      style={{ width: `${healthPct}%` }}
                    />
                  </div>
                  <span className="text-sm text-gray-400 w-20 text-right">
                    {dtype.healthy_count}/{dtype.total}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Trend Stats */}
      <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-gray-700">
        <div className="text-center">
          <p className="text-xl font-bold text-yellow-400">{trends.status_changes_total}</p>
          <p className="text-xs text-gray-400">State Changes (30d)</p>
        </div>
        <div className="text-center">
          <p className="text-xl font-bold text-blue-400">{summary.detections_with_history}</p>
          <p className="text-xs text-gray-400">Tracked Detections</p>
        </div>
      </div>

      {/* Last Updated */}
      <div className="mt-4 pt-4 border-t border-gray-700 text-center">
        <p className="text-xs text-gray-500">
          Last updated:{' '}
          {new Date(data.generated_at).toLocaleString('en-GB', {
            day: 'numeric',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
          })}
        </p>
      </div>
    </div>
  )
}
