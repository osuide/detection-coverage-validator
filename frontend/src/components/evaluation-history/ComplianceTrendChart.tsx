/**
 * Compliance Trend Chart Component.
 *
 * Displays a line/area chart showing health percentage over time
 * with period selectors and interactive tooltips.
 */

import { useState } from 'react'
import { TrendingUp, TrendingDown, Minus, Calendar } from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts'
import { TrendDataPoint } from '../../services/api'

interface ComplianceTrendChartProps {
  data: TrendDataPoint[]
  isLoading?: boolean
  comparison?: {
    trend: 'improving' | 'stable' | 'declining'
    health_change_percent: number
  }
  onPeriodChange?: (days: number) => void
}

const periodOptions = [
  { label: '7D', days: 7 },
  { label: '30D', days: 30 },
  { label: '90D', days: 90 },
]

function TrendIndicator({ trend, change }: { trend: string; change: number }) {
  const config = {
    improving: {
      icon: TrendingUp,
      colour: 'text-green-400',
      bgColour: 'bg-green-900/30',
      label: 'Improving',
    },
    declining: {
      icon: TrendingDown,
      colour: 'text-red-400',
      bgColour: 'bg-red-900/30',
      label: 'Declining',
    },
    stable: {
      icon: Minus,
      colour: 'text-gray-400',
      bgColour: 'bg-gray-700/30',
      label: 'Stable',
    },
  }

  const { icon: Icon, colour, bgColour, label } = config[trend as keyof typeof config] || config.stable

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full ${bgColour}`}>
      <Icon className={`h-4 w-4 ${colour}`} />
      <span className={`text-sm font-medium ${colour}`}>{label}</span>
      {change !== 0 && (
        <span className={`text-xs ${colour}`}>
          {change > 0 ? '+' : ''}{change.toFixed(1)}%
        </span>
      )}
    </div>
  )
}

function CustomTooltip({ active, payload }: { active?: boolean; payload?: Array<{ value: number; payload: TrendDataPoint }>; label?: string }) {
  if (!active || !payload || !payload.length) return null

  const data = payload[0].payload

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 shadow-lg">
      <p className="text-gray-400 text-xs mb-2">
        {new Date(data.date).toLocaleDateString('en-GB', {
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        })}
      </p>
      <div className="space-y-1">
        <div className="flex items-center justify-between gap-4">
          <span className="text-sm text-gray-300">Health</span>
          <span className="text-sm font-medium text-green-400">
            {data.health_percentage.toFixed(1)}%
          </span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <span className="text-sm text-gray-300">Healthy</span>
          <span className="text-sm text-green-400">{data.healthy_count}</span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <span className="text-sm text-gray-300">Unhealthy</span>
          <span className="text-sm text-red-400">{data.unhealthy_count}</span>
        </div>
        {data.state_changes > 0 && (
          <div className="flex items-center justify-between gap-4 pt-1 border-t border-gray-700">
            <span className="text-sm text-gray-300">Changes</span>
            <span className="text-sm text-yellow-400">{data.state_changes}</span>
          </div>
        )}
      </div>
    </div>
  )
}

export function ComplianceTrendChart({
  data,
  isLoading,
  comparison,
  onPeriodChange,
}: ComplianceTrendChartProps) {
  const [selectedPeriod, setSelectedPeriod] = useState(30)

  const handlePeriodChange = (days: number) => {
    setSelectedPeriod(days)
    onPeriodChange?.(days)
  }

  if (isLoading) {
    return (
      <div className="card p-6">
        <div className="animate-pulse">
          <div className="flex items-center justify-between mb-4">
            <div className="h-6 bg-gray-700 rounded-sm w-48" />
            <div className="h-8 bg-gray-700 rounded-sm w-32" />
          </div>
          <div className="h-64 bg-gray-700/50 rounded-sm" />
        </div>
      </div>
    )
  }

  if (!data.length) {
    return (
      <div className="card p-6">
        <div className="flex items-center gap-2 mb-4">
          <Calendar className="h-5 w-5 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">Compliance Trend</h3>
        </div>
        <div className="flex items-center justify-center h-64 text-gray-400">
          <p>No trend data available yet. Run a scan to start tracking.</p>
        </div>
      </div>
    )
  }

  // Calculate average for reference line
  const avgHealth = data.reduce((sum, d) => sum + d.health_percentage, 0) / data.length

  return (
    <div className="card p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Calendar className="h-5 w-5 text-gray-400" />
            <h3 className="text-lg font-semibold text-white">Compliance Trend</h3>
          </div>
          {comparison && (
            <TrendIndicator trend={comparison.trend} change={comparison.health_change_percent} />
          )}
        </div>

        {/* Period Selector */}
        <div className="flex items-center gap-1 bg-gray-700/50 rounded-lg p-1">
          {periodOptions.map((option) => (
            <button
              key={option.days}
              onClick={() => handlePeriodChange(option.days)}
              className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                selectedPeriod === option.days
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {/* Chart - Use fixed height to prevent Recharts -1 dimension error during render */}
      <div className="min-w-0">
        <ResponsiveContainer width="100%" height={256}>
          <AreaChart
            data={data}
            margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
          >
            <defs>
              <linearGradient id="healthGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis
              dataKey="date"
              stroke="#6b7280"
              tick={{ fill: '#9ca3af', fontSize: 12 }}
              tickFormatter={(value) =>
                new Date(value).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
              }
            />
            <YAxis
              stroke="#6b7280"
              tick={{ fill: '#9ca3af', fontSize: 12 }}
              domain={[0, 100]}
              tickFormatter={(value) => `${value}%`}
            />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine
              y={avgHealth}
              stroke="#6b7280"
              strokeDasharray="5 5"
              label={{
                value: `Avg: ${avgHealth.toFixed(1)}%`,
                position: 'right',
                fill: '#6b7280',
                fontSize: 11,
              }}
            />
            <Area
              type="monotone"
              dataKey="health_percentage"
              stroke="#22c55e"
              strokeWidth={2}
              fill="url(#healthGradient)"
              dot={{ fill: '#22c55e', strokeWidth: 0, r: 3 }}
              activeDot={{ r: 5, stroke: '#22c55e', strokeWidth: 2, fill: '#1f2937' }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-3 gap-4 mt-6 pt-4 border-t border-gray-700">
        <div className="text-center">
          <p className="text-2xl font-bold text-white">
            {data[data.length - 1]?.health_percentage.toFixed(1)}%
          </p>
          <p className="text-xs text-gray-400">Current Health</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-white">{avgHealth.toFixed(1)}%</p>
          <p className="text-xs text-gray-400">Average</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-bold text-yellow-400">
            {data.reduce((sum, d) => sum + d.state_changes, 0)}
          </p>
          <p className="text-xs text-gray-400">Total Changes</p>
        </div>
      </div>
    </div>
  )
}
