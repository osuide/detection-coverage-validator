/**
 * Technique Detail Modal Component.
 *
 * Displays detailed technique information when clicking on coverage stat cards.
 * Shows techniques grouped by status with detection details and template links.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  X,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Shield,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  FileCode,
} from 'lucide-react'
import { TechniqueCoverage } from '../../services/api'

interface TechniqueDetailModalProps {
  isOpen: boolean
  onClose: () => void
  title: string
  description: string
  techniques: TechniqueCoverage[]
  variant: 'covered' | 'partial' | 'uncovered' | 'total'
}

const variantConfig = {
  covered: {
    icon: CheckCircle,
    iconColour: 'text-green-400',
    bgColour: 'bg-green-900/20',
    borderColour: 'border-green-700',
  },
  partial: {
    icon: AlertTriangle,
    iconColour: 'text-yellow-400',
    bgColour: 'bg-yellow-900/20',
    borderColour: 'border-yellow-700',
  },
  uncovered: {
    icon: XCircle,
    iconColour: 'text-red-400',
    bgColour: 'bg-red-900/20',
    borderColour: 'border-red-700',
  },
  total: {
    icon: Shield,
    iconColour: 'text-blue-400',
    bgColour: 'bg-blue-900/20',
    borderColour: 'border-blue-700',
  },
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'covered':
      return <CheckCircle className="w-4 h-4 text-green-400" />
    case 'partial':
      return <AlertTriangle className="w-4 h-4 text-yellow-400" />
    case 'uncovered':
      return <XCircle className="w-4 h-4 text-red-400" />
    default:
      return <Shield className="w-4 h-4 text-gray-400" />
  }
}

function getConfidenceBadgeStyle(confidence: number) {
  if (confidence >= 0.8) return 'bg-green-900/50 text-green-300 border-green-700'
  if (confidence >= 0.6) return 'bg-yellow-900/50 text-yellow-300 border-yellow-700'
  if (confidence >= 0.4) return 'bg-orange-900/50 text-orange-300 border-orange-700'
  return 'bg-gray-700 text-gray-300 border-gray-600'
}

// Expandable technique row component
function ExpandableTechniqueRow({
  technique,
}: {
  technique: TechniqueCoverage
}) {
  const [isExpanded, setIsExpanded] = useState(false)

  const hasDetections = technique.detection_count > 0
  const canExpand = hasDetections

  return (
    <div className="bg-gray-700/30 rounded-lg overflow-hidden">
      {/* Technique header - clickable */}
      <div
        className={`p-4 ${canExpand ? 'cursor-pointer hover:bg-gray-700/50' : ''} transition-colors`}
        onClick={() => canExpand && setIsExpanded(!isExpanded)}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-2">
            {canExpand && (
              <div className="mt-0.5">
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-gray-400" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-gray-400" />
                )}
              </div>
            )}
            {!canExpand && (
              <div className="mt-0.5">
                {getStatusIcon(technique.status)}
              </div>
            )}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm text-blue-400">
                  {technique.technique_id}
                </span>
                {canExpand && (
                  <span className="text-xs text-gray-500">
                    Click to see detections
                  </span>
                )}
              </div>
              <p className="text-sm text-white" title={technique.technique_name}>
                {technique.technique_name}
              </p>
              <p className="text-xs text-gray-500 mt-1">{technique.tactic_name}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 ml-4">
            {/* Confidence badge */}
            {technique.max_confidence > 0 && (
              <span
                className={`px-2 py-0.5 text-xs font-medium rounded border ${getConfidenceBadgeStyle(technique.max_confidence)}`}
              >
                {Math.round(technique.max_confidence * 100)}%
              </span>
            )}
            {/* Detection count */}
            <div className="text-right">
              <div className="text-sm font-medium text-white">
                {technique.detection_count}
              </div>
              <div className="text-xs text-gray-400">detections</div>
            </div>
          </div>
        </div>

        {/* Action buttons for uncovered techniques */}
        {technique.status === 'uncovered' && (
          <div className="mt-3 ml-6 flex items-center gap-2">
            {technique.has_template ? (
              <Link
                to={`/techniques/${technique.technique_id}`}
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-green-900/50 text-green-300 border border-green-700 rounded hover:bg-green-800/50 transition-colors"
              >
                <FileCode className="w-3 h-3" />
                View Template
              </Link>
            ) : (
              <a
                href={`https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium bg-gray-700 text-gray-400 border border-gray-600 rounded hover:bg-gray-600 transition-colors"
              >
                <ExternalLink className="w-3 h-3" />
                MITRE ATT&CK
              </a>
            )}
          </div>
        )}
      </div>

      {/* Expanded detection details */}
      {isExpanded && hasDetections && (
        <div className="border-t border-gray-700 p-4 bg-gray-800/50">
          <div className="text-xs font-medium text-gray-400 mb-2">
            Detections providing coverage:
          </div>
          <div className="space-y-1">
            {technique.detection_names.map((name, index) => (
              <div
                key={index}
                className="flex items-center gap-2 text-sm text-gray-300 pl-2"
              >
                <span className="text-gray-500">└─</span>
                <CheckCircle className="w-3 h-3 text-green-400" />
                <span>{name}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function TechniqueDetailModal({
  isOpen,
  onClose,
  title,
  description,
  techniques,
  variant,
}: TechniqueDetailModalProps) {
  if (!isOpen) return null

  const config = variantConfig[variant]
  const Icon = config.icon

  // Group techniques by tactic for better organisation
  const tacticGroups = techniques.reduce(
    (acc, technique) => {
      const tactic = technique.tactic_name
      if (!acc[tactic]) {
        acc[tactic] = []
      }
      acc[tactic].push(technique)
      return acc
    },
    {} as Record<string, TechniqueCoverage[]>
  )

  // Sort tactics alphabetically
  const sortedTactics = Object.keys(tacticGroups).sort()

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative min-h-screen flex items-center justify-center p-4">
        <div className="relative bg-gray-800 rounded-xl shadow-xl max-w-4xl w-full max-h-[80vh] flex flex-col">
          {/* Header */}
          <div
            className={`px-6 py-4 border-b ${config.borderColour} flex items-center justify-between`}
          >
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${config.bgColour}`}>
                <Icon className={`w-5 h-5 ${config.iconColour}`} />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">{title}</h2>
                <p className="text-sm text-gray-400">{techniques.length} techniques</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>

          {/* Description */}
          <div className="px-6 py-3 border-b border-gray-700 bg-gray-750">
            <p className="text-sm text-gray-300">{description}</p>
          </div>

          {/* Techniques List - grouped by tactic */}
          <div className="flex-1 overflow-y-auto px-6 py-4">
            {techniques.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                No techniques in this category
              </div>
            ) : (
              <div className="space-y-6">
                {sortedTactics.map((tactic) => (
                  <div key={tactic}>
                    <h3 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      {tactic}
                      <span className="text-gray-500">
                        ({tacticGroups[tactic].length})
                      </span>
                    </h3>
                    <div className="space-y-2">
                      {tacticGroups[tactic].map((technique) => (
                        <ExpandableTechniqueRow
                          key={technique.technique_id}
                          technique={technique}
                        />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="px-6 py-4 border-t border-gray-700 flex justify-end">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default TechniqueDetailModal
