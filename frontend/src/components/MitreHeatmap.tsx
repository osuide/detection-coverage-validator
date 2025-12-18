import { useState } from 'react'
import { ExternalLink } from 'lucide-react'

interface TechniqueCell {
  technique_id: string
  technique_name: string
  tactic_id: string
  detection_count: number
  max_confidence: number
  status: 'covered' | 'partial' | 'uncovered'
}

interface MitreHeatmapProps {
  techniques: TechniqueCell[]
  onTechniqueClick?: (techniqueId: string) => void
}

// MITRE ATT&CK Tactics in order
const TACTICS = [
  { id: 'TA0001', name: 'Initial Access', short: 'Initial Access' },
  { id: 'TA0002', name: 'Execution', short: 'Execution' },
  { id: 'TA0003', name: 'Persistence', short: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation', short: 'Priv Esc' },
  { id: 'TA0005', name: 'Defense Evasion', short: 'Def Evasion' },
  { id: 'TA0006', name: 'Credential Access', short: 'Cred Access' },
  { id: 'TA0007', name: 'Discovery', short: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement', short: 'Lateral Mov' },
  { id: 'TA0009', name: 'Collection', short: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration', short: 'Exfiltration' },
  { id: 'TA0011', name: 'Command and Control', short: 'C2' },
  { id: 'TA0040', name: 'Impact', short: 'Impact' },
]

function getCellColor(status: string, detectionCount: number): string {
  if (status === 'uncovered' || detectionCount === 0) {
    return 'bg-gray-200 hover:bg-gray-300'
  }
  if (status === 'partial') {
    return 'bg-yellow-400 hover:bg-yellow-500'
  }
  // Covered - vary by detection count
  if (detectionCount === 1) {
    return 'bg-green-300 hover:bg-green-400'
  }
  if (detectionCount === 2) {
    return 'bg-green-400 hover:bg-green-500'
  }
  return 'bg-green-500 hover:bg-green-600'
}

export default function MitreHeatmap({ techniques, onTechniqueClick }: MitreHeatmapProps) {
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueCell | null>(null)

  // Group techniques by tactic
  const techniquesByTactic: Record<string, TechniqueCell[]> = {}
  TACTICS.forEach(tactic => {
    techniquesByTactic[tactic.id] = techniques.filter(t => t.tactic_id === tactic.id)
  })

  // Note: maxTechniquesPerTactic can be used for grid layout if needed
  // Currently using flexible layout that adapts to content

  const handleCellClick = (technique: TechniqueCell) => {
    setSelectedTechnique(technique)
    onTechniqueClick?.(technique.technique_id)
  }

  return (
    <div>
      {/* Legend */}
      <div className="flex items-center space-x-6 mb-4 text-sm">
        <div className="flex items-center">
          <div className="w-4 h-4 bg-gray-200 rounded mr-2"></div>
          <span className="text-gray-600">No Coverage</span>
        </div>
        <div className="flex items-center">
          <div className="w-4 h-4 bg-yellow-400 rounded mr-2"></div>
          <span className="text-gray-600">Partial</span>
        </div>
        <div className="flex items-center">
          <div className="w-4 h-4 bg-green-300 rounded mr-2"></div>
          <span className="text-gray-600">1 Detection</span>
        </div>
        <div className="flex items-center">
          <div className="w-4 h-4 bg-green-500 rounded mr-2"></div>
          <span className="text-gray-600">2+ Detections</span>
        </div>
      </div>

      {/* Heatmap Grid */}
      <div className="overflow-x-auto">
        <div className="inline-flex gap-1 min-w-full">
          {TACTICS.map(tactic => {
            const tacticTechniques = techniquesByTactic[tactic.id] || []

            return (
              <div key={tactic.id} className="flex-1 min-w-[100px]">
                {/* Tactic Header */}
                <div className="text-xs font-semibold text-gray-700 text-center p-2 bg-gray-100 rounded-t border-b border-gray-200">
                  {tactic.short}
                </div>

                {/* Technique Cells */}
                <div className="space-y-1 p-1 bg-gray-50 rounded-b min-h-[200px]">
                  {tacticTechniques.length > 0 ? (
                    tacticTechniques.map(technique => (
                      <button
                        key={technique.technique_id}
                        onClick={() => handleCellClick(technique)}
                        className={`w-full p-2 rounded text-xs font-medium text-center transition-colors cursor-pointer ${getCellColor(technique.status, technique.detection_count)} ${
                          selectedTechnique?.technique_id === technique.technique_id
                            ? 'ring-2 ring-blue-500 ring-offset-1'
                            : ''
                        }`}
                        title={`${technique.technique_id}: ${technique.technique_name}`}
                      >
                        <div className="truncate text-gray-800">
                          {technique.technique_id}
                        </div>
                      </button>
                    ))
                  ) : (
                    <div className="text-xs text-gray-400 text-center py-4">
                      No techniques
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Selected Technique Detail */}
      {selectedTechnique && (
        <div className="mt-4 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="font-semibold text-gray-900">
                {selectedTechnique.technique_id} - {selectedTechnique.technique_name}
              </h4>
              <p className="text-sm text-gray-600 mt-1">
                {selectedTechnique.detection_count > 0 ? (
                  <>
                    Covered by <span className="font-medium">{selectedTechnique.detection_count}</span> detection(s)
                    {' '}&bull;{' '}
                    Confidence: <span className="font-medium">{(selectedTechnique.max_confidence * 100).toFixed(0)}%</span>
                  </>
                ) : (
                  <span className="text-red-600">No detections covering this technique</span>
                )}
              </p>
            </div>
            <a
              href={`https://attack.mitre.org/techniques/${selectedTechnique.technique_id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center text-sm text-blue-600 hover:text-blue-700"
            >
              View in MITRE
              <ExternalLink className="h-4 w-4 ml-1" />
            </a>
          </div>
        </div>
      )}
    </div>
  )
}
