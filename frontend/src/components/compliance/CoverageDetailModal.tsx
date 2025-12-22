/**
 * Coverage Detail Modal Component.
 *
 * Displays detailed control information when clicking on coverage stat cards.
 * Shows controls grouped by status or cloud category with coverage details.
 */

import { X, CheckCircle, AlertTriangle, XCircle, MinusCircle, Shield } from 'lucide-react'
import { ControlStatusItem } from '../../services/complianceApi'

interface CoverageDetailModalProps {
  isOpen: boolean
  onClose: () => void
  title: string
  description: string
  controls: ControlStatusItem[]
  variant: 'covered' | 'partial' | 'uncovered' | 'not_assessable' | 'cloud'
}

const variantConfig = {
  covered: {
    icon: CheckCircle,
    iconColor: 'text-green-400',
    bgColor: 'bg-green-900/20',
    borderColor: 'border-green-700',
    barColor: 'bg-green-500',
  },
  partial: {
    icon: AlertTriangle,
    iconColor: 'text-yellow-400',
    bgColor: 'bg-yellow-900/20',
    borderColor: 'border-yellow-700',
    barColor: 'bg-yellow-500',
  },
  uncovered: {
    icon: XCircle,
    iconColor: 'text-red-400',
    bgColor: 'bg-red-900/20',
    borderColor: 'border-red-700',
    barColor: 'bg-red-500',
  },
  not_assessable: {
    icon: MinusCircle,
    iconColor: 'text-gray-400',
    bgColor: 'bg-gray-700/30',
    borderColor: 'border-gray-600',
    barColor: 'bg-gray-500',
  },
  cloud: {
    icon: Shield,
    iconColor: 'text-blue-400',
    bgColor: 'bg-blue-900/20',
    borderColor: 'border-blue-700',
    barColor: 'bg-blue-500',
  },
}

function getPriorityBadge(priority: string | null) {
  if (!priority) return null

  const styles: Record<string, string> = {
    P1: 'bg-red-900/50 text-red-300 border-red-700',
    P2: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
    P3: 'bg-blue-900/50 text-blue-300 border-blue-700',
  }

  return (
    <span className={`px-1.5 py-0.5 text-xs font-medium rounded border ${styles[priority] || 'bg-gray-700 text-gray-300'}`}>
      {priority}
    </span>
  )
}

export function CoverageDetailModal({
  isOpen,
  onClose,
  title,
  description,
  controls,
  variant,
}: CoverageDetailModalProps) {
  if (!isOpen) return null

  const config = variantConfig[variant]
  const Icon = config.icon

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative min-h-screen flex items-center justify-center p-4">
        <div className="relative bg-gray-800 rounded-xl shadow-xl max-w-2xl w-full max-h-[80vh] flex flex-col">
          {/* Header */}
          <div className={`px-6 py-4 border-b ${config.borderColor} flex items-center justify-between`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${config.bgColor}`}>
                <Icon className={`w-5 h-5 ${config.iconColor}`} />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">{title}</h2>
                <p className="text-sm text-gray-400">{controls.length} controls</p>
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

          {/* Controls List */}
          <div className="flex-1 overflow-y-auto px-6 py-4">
            {controls.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                No controls in this category
              </div>
            ) : (
              <div className="space-y-3">
                {controls.map((control) => (
                  <div
                    key={control.control_id}
                    className="bg-gray-700/30 rounded-lg p-4 hover:bg-gray-700/50 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-sm text-blue-400">
                            {control.control_id}
                          </span>
                          {getPriorityBadge(control.priority)}
                        </div>
                        <p className="text-sm text-white truncate" title={control.control_name}>
                          {control.control_name}
                        </p>
                        <p className="text-xs text-gray-500 mt-1">{control.control_family}</p>
                      </div>
                      <div className="text-right ml-4">
                        <div className="text-sm font-medium text-white">
                          {control.covered_techniques}/{control.mapped_techniques}
                        </div>
                        <div className="text-xs text-gray-400">techniques</div>
                      </div>
                    </div>

                    {/* Coverage bar */}
                    {control.mapped_techniques > 0 && (
                      <div className="mt-3">
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="text-gray-400">Coverage</span>
                          <span className={control.coverage_percent >= 80 ? 'text-green-400' : control.coverage_percent >= 40 ? 'text-yellow-400' : 'text-red-400'}>
                            {control.coverage_percent.toFixed(0)}%
                          </span>
                        </div>
                        <div className="w-full h-1.5 bg-gray-600 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${config.barColor}`}
                            style={{ width: `${Math.min(control.coverage_percent, 100)}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Responsibility badge */}
                    {control.shared_responsibility && (
                      <div className="mt-2 flex items-center gap-2">
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          control.shared_responsibility === 'customer'
                            ? 'bg-blue-900/50 text-blue-300'
                            : control.shared_responsibility === 'provider'
                            ? 'bg-purple-900/50 text-purple-300'
                            : 'bg-gray-600 text-gray-300'
                        }`}>
                          {control.shared_responsibility === 'customer' ? 'Customer' :
                           control.shared_responsibility === 'provider' ? 'Provider' : 'Shared'}
                        </span>
                      </div>
                    )}
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
