import { TacticCoverage } from '../services/api'

interface TacticHeatmapProps {
  tactics: TacticCoverage[]
}

// MITRE ATT&CK Cloud Matrix tactic order
// Based on official Cloud Matrix (11 tactics) + C2 (detectable via VPC Flow Logs, GuardDuty)
// Excludes Reconnaissance (TA0043) and Resource Development (TA0042) as they are PRE-compromise
const TACTIC_ORDER = [
  'TA0001', // Initial Access
  'TA0002', // Execution
  'TA0003', // Persistence
  'TA0004', // Privilege Escalation
  'TA0005', // Defense Evasion
  'TA0006', // Credential Access
  'TA0007', // Discovery
  'TA0008', // Lateral Movement
  'TA0009', // Collection
  'TA0011', // Command and Control
  'TA0010', // Exfiltration
  'TA0040', // Impact
]

export default function TacticHeatmap({ tactics }: TacticHeatmapProps) {
  const getColor = (percent: number) => {
    if (percent >= 70) return 'bg-green-500'
    if (percent >= 40) return 'bg-yellow-500'
    if (percent > 0) return 'bg-orange-500'
    return 'bg-gray-600'
  }

  const sortedTactics = [...tactics].sort((a, b) => {
    const aIndex = TACTIC_ORDER.indexOf(a.tactic_id)
    const bIndex = TACTIC_ORDER.indexOf(b.tactic_id)
    if (aIndex === -1) return 1
    if (bIndex === -1) return -1
    return aIndex - bIndex
  })

  return (
    <div className="space-y-2">
      {sortedTactics.map((tactic) => (
        <div key={tactic.tactic_id} className="flex items-center">
          <div className="w-40 text-sm text-white truncate" title={tactic.tactic_name}>
            {tactic.tactic_name}
          </div>
          <div className="flex-1 mx-3">
            <div className="h-6 bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full ${getColor(tactic.percent)} transition-all duration-300`}
                style={{ width: `${tactic.percent}%` }}
              />
            </div>
          </div>
          <div className="w-24 text-right">
            <span className="text-sm font-medium text-white">
              {tactic.covered}/{tactic.total}
            </span>
            <span className="text-sm text-gray-400 ml-1">
              ({tactic.percent.toFixed(0)}%)
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}
