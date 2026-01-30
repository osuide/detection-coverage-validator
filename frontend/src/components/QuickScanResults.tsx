import {
  Shield,
  ShieldAlert,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Layers,
} from 'lucide-react'
import type { QuickScanResponse } from '../services/quickScanApi'

interface Props {
  data: QuickScanResponse
}

/* ---------- helpers ---------- */

function coverageColour(pct: number): string {
  if (pct >= 60) return 'text-green-400'
  if (pct >= 30) return 'text-yellow-400'
  return 'text-red-400'
}

function barColour(pct: number): string {
  if (pct >= 60) return 'bg-green-500'
  if (pct >= 30) return 'bg-yellow-500'
  return 'bg-red-500'
}

function priorityBadge(priority: string) {
  const base = 'text-xs px-2 py-0.5 rounded-full font-medium'
  switch (priority.toLowerCase()) {
    case 'critical':
      return `${base} text-red-400 bg-red-500/20`
    case 'high':
      return `${base} text-orange-400 bg-orange-500/20`
    case 'medium':
      return `${base} text-yellow-400 bg-yellow-500/20`
    default:
      return `${base} text-gray-400 bg-gray-600/30`
  }
}

/* ---------- component ---------- */

export default function QuickScanResults({ data }: Props) {
  const { summary, tactic_coverage, top_gaps, detections } = data

  return (
    <div className="space-y-6">
      {/* ---- Summary card ---- */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-lg bg-blue-500/10">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <h2 className="text-lg font-semibold text-white">Coverage Summary</h2>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Stat
            label="Coverage"
            value={`${summary.coverage_percentage.toFixed(1)}%`}
            className={coverageColour(summary.coverage_percentage)}
          />
          <Stat label="Techniques Covered" value={summary.covered_techniques} />
          <Stat label="Detections Found" value={summary.detections_found} />
          <Stat label="Resources Parsed" value={summary.resources_parsed} />
        </div>

        {summary.truncated && (
          <p className="mt-3 text-xs text-yellow-400">
            Results were truncated — only the first 500 detections are shown.
          </p>
        )}
      </div>

      {/* ---- Tactic coverage bars ---- */}
      {Object.keys(tactic_coverage).length > 0 && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-purple-500/10">
              <Layers className="w-5 h-5 text-purple-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Tactic Coverage</h2>
          </div>

          <div className="space-y-3">
            {Object.entries(tactic_coverage)
              .sort(([, a], [, b]) => b.percentage - a.percentage)
              .map(([tactic, info]) => (
                <div key={tactic}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-gray-300 truncate pr-4">{tactic}</span>
                    <span className={`text-sm font-medium ${coverageColour(info.percentage)}`}>
                      {info.percentage.toFixed(0)}%
                      <span className="text-gray-500 font-normal ml-1">
                        ({info.covered}/{info.total})
                      </span>
                    </span>
                  </div>
                  <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${barColour(info.percentage)}`}
                      style={{ width: `${Math.min(info.percentage, 100)}%` }}
                    />
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* ---- Top gaps ---- */}
      {top_gaps.length > 0 && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-red-500/10">
              <ShieldAlert className="w-5 h-5 text-red-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Top Coverage Gaps</h2>
          </div>

          <div className="divide-y divide-gray-700">
            {top_gaps.map((gap) => (
              <div
                key={`${gap.technique_id}-${gap.tactic_name}`}
                className="py-3 first:pt-0 last:pb-0 flex items-center justify-between gap-4"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />
                    <span className="text-sm font-medium text-white truncate">
                      {gap.technique_id} — {gap.technique_name}
                    </span>
                  </div>
                  <span className="text-xs text-gray-500 ml-6">{gap.tactic_name}</span>
                </div>
                <span className={priorityBadge(gap.priority)}>{gap.priority}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ---- Detected resources ---- */}
      {detections.length > 0 && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-green-500/10">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">
              Detected Resources ({detections.length})
            </h2>
          </div>

          <div className="divide-y divide-gray-700">
            {detections.map((det, i) => (
              <div
                key={i}
                className="py-3 first:pt-0 last:pb-0 flex items-center gap-3"
              >
                <ChevronRight className="h-4 w-4 text-gray-500 shrink-0" />
                <div className="min-w-0">
                  <span className="text-sm text-white truncate block">{det.name}</span>
                  <span className="text-xs text-gray-500">{det.detection_type}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* ---------- internal ---------- */

function Stat({
  label,
  value,
  className = 'text-white',
}: {
  label: string
  value: string | number
  className?: string
}) {
  return (
    <div>
      <p className="text-xs text-gray-400 mb-1">{label}</p>
      <p className={`text-2xl font-bold ${className}`}>{value}</p>
    </div>
  )
}
