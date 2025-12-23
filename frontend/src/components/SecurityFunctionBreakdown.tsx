/**
 * SecurityFunctionBreakdown - NIST CSF security function display
 *
 * Shows how detections are categorised by security function:
 * - Detect: Threat detection (MITRE ATT&CK mapped)
 * - Protect: Preventive controls
 * - Identify: Visibility/posture
 * - Recover: Backup/DR
 * - Operational: Non-security (tagging, cost)
 */

import { Shield, Lock, Eye, RotateCcw, Settings } from 'lucide-react'
import { SecurityFunctionBreakdown as BreakdownType } from '../services/api'

interface Props {
  breakdown: BreakdownType
  compact?: boolean
}

const FUNCTION_CONFIG = [
  {
    key: 'detect' as const,
    label: 'Detect',
    description: 'Threat Detection (MITRE)',
    colour: 'text-red-500',
    bgColour: 'bg-red-500/10',
    Icon: Shield,
  },
  {
    key: 'protect' as const,
    label: 'Protect',
    description: 'Preventive Controls',
    colour: 'text-blue-500',
    bgColour: 'bg-blue-500/10',
    Icon: Lock,
  },
  {
    key: 'identify' as const,
    label: 'Identify',
    description: 'Visibility/Posture',
    colour: 'text-purple-500',
    bgColour: 'bg-purple-500/10',
    Icon: Eye,
  },
  {
    key: 'recover' as const,
    label: 'Recover',
    description: 'Backup/DR',
    colour: 'text-green-500',
    bgColour: 'bg-green-500/10',
    Icon: RotateCcw,
  },
  {
    key: 'operational' as const,
    label: 'Operational',
    description: 'Non-security',
    colour: 'text-gray-500',
    bgColour: 'bg-gray-500/10',
    Icon: Settings,
  },
]

export function SecurityFunctionBreakdown({ breakdown, compact = false }: Props) {
  const total = breakdown.total || 1 // Avoid division by zero

  if (compact) {
    // Compact horizontal layout for cards
    return (
      <div className="flex items-center gap-3 text-sm">
        {FUNCTION_CONFIG.filter(f => breakdown[f.key] > 0).map(({ key, label, colour, bgColour, Icon }) => (
          <div
            key={key}
            className={`flex items-center gap-1.5 px-2 py-1 rounded ${bgColour}`}
          >
            <Icon className={`h-3.5 w-3.5 ${colour}`} />
            <span className={`font-medium ${colour}`}>{breakdown[key]}</span>
            <span className="text-gray-400">{label}</span>
          </div>
        ))}
      </div>
    )
  }

  // Full vertical layout with progress bars
  return (
    <div className="space-y-3">
      <h4 className="text-sm font-medium text-gray-300">Security Functions (NIST CSF)</h4>
      {FUNCTION_CONFIG.map(({ key, label, description, colour, bgColour, Icon }) => {
        const count = breakdown[key]
        const percent = (count / total) * 100

        return (
          <div key={key} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2">
                <div className={`p-1 rounded ${bgColour}`}>
                  <Icon className={`h-4 w-4 ${colour}`} />
                </div>
                <span className="text-gray-300">{label}</span>
                <span className="text-gray-500 text-xs">({description})</span>
              </div>
              <span className={`font-medium ${colour}`}>{count}</span>
            </div>
            <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${bgColour.replace('/10', '')}`}
                style={{ width: `${percent}%` }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default SecurityFunctionBreakdown
