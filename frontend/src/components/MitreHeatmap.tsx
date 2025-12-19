import { useState } from 'react'
import { ExternalLink } from 'lucide-react'

interface TechniqueCell {
  technique_id: string
  technique_name: string
  tactic_id: string
  detection_count: number
  max_confidence: number
  status: 'covered' | 'partial' | 'uncovered'
  detection_names?: string[]
}

interface TooltipState {
  technique: TechniqueCell
  x: number
  y: number
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
  const [tooltip, setTooltip] = useState<TooltipState | null>(null)

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

  const handleMouseEnter = (technique: TechniqueCell, event: React.MouseEvent) => {
    const rect = event.currentTarget.getBoundingClientRect()
    setTooltip({
      technique,
      x: rect.left + rect.width / 2,
      y: rect.top - 10,
    })
  }

  const handleMouseLeave = () => {
    setTooltip(null)
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
                        onMouseEnter={(e) => handleMouseEnter(technique, e)}
                        onMouseLeave={handleMouseLeave}
                        className={`w-full p-2 rounded text-xs font-medium text-center transition-colors cursor-pointer ${getCellColor(technique.status, technique.detection_count)} ${
                          selectedTechnique?.technique_id === technique.technique_id
                            ? 'ring-2 ring-blue-500 ring-offset-1'
                            : ''
                        }`}
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

      {/* Hover Tooltip */}
      {tooltip && (
        <div
          className="fixed z-50 bg-gray-900 text-white rounded-lg shadow-xl p-3 text-sm pointer-events-none transform -translate-x-1/2 -translate-y-full max-w-xs"
          style={{
            left: tooltip.x,
            top: tooltip.y,
          }}
        >
          <div className="font-semibold text-cyan-300 mb-1">
            {tooltip.technique.technique_id}
          </div>
          <div className="text-gray-100 mb-2">
            {tooltip.technique.technique_name}
          </div>
          <div className="space-y-1 text-xs">
            <div className="flex justify-between gap-4">
              <span className="text-gray-400">Confidence:</span>
              <span className="font-medium">
                {tooltip.technique.max_confidence > 0
                  ? `${(tooltip.technique.max_confidence * 100).toFixed(0)}%`
                  : 'N/A'}
              </span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-gray-400">Detections:</span>
              <span className="font-medium">{tooltip.technique.detection_count}</span>
            </div>
            <div className="flex justify-between gap-4">
              <span className="text-gray-400">Status:</span>
              <span className={`font-medium capitalize ${
                tooltip.technique.status === 'covered' ? 'text-green-400' :
                tooltip.technique.status === 'partial' ? 'text-yellow-400' :
                'text-gray-400'
              }`}>
                {tooltip.technique.status}
              </span>
            </div>
          </div>
          {/* Detection names list */}
          {tooltip.technique.detection_names && tooltip.technique.detection_names.length > 0 && (
            <div className="mt-2 pt-2 border-t border-gray-700">
              <div className="text-xs text-gray-400 mb-1">Mapped Detections:</div>
              <ul className="text-xs space-y-0.5 max-h-24 overflow-y-auto">
                {tooltip.technique.detection_names.slice(0, 5).map((name, idx) => (
                  <li key={idx} className="text-gray-200 truncate flex items-start gap-1">
                    <span className="text-green-400 flex-shrink-0">•</span>
                    <span className="truncate">{name}</span>
                  </li>
                ))}
                {tooltip.technique.detection_names.length > 5 && (
                  <li className="text-gray-400 italic">
                    +{tooltip.technique.detection_names.length - 5} more...
                  </li>
                )}
              </ul>
            </div>
          )}
          {/* Tooltip arrow */}
          <div className="absolute left-1/2 bottom-0 transform -translate-x-1/2 translate-y-full">
            <div className="border-8 border-transparent border-t-gray-900"></div>
          </div>
        </div>
      )}

      {/* Selected Technique Detail */}
      {selectedTechnique && (
        <div className="mt-4 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <div className="flex items-start justify-between">
            <div className="flex-1">
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
              {/* Detection names list */}
              {selectedTechnique.detection_names && selectedTechnique.detection_names.length > 0 && (
                <div className="mt-3">
                  <p className="text-xs font-medium text-gray-500 mb-1">Mapped Detections:</p>
                  <ul className="text-sm space-y-1">
                    {selectedTechnique.detection_names.map((name, idx) => (
                      <li key={idx} className="text-gray-700 flex items-start gap-2">
                        <span className="text-green-600 flex-shrink-0">✓</span>
                        <span>{name}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <a
              href={`https://attack.mitre.org/techniques/${selectedTechnique.technique_id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center text-sm text-blue-600 hover:text-blue-700 flex-shrink-0 ml-4"
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
