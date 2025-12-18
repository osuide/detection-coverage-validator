import { useQuery } from '@tanstack/react-query'
import { X, ExternalLink, Shield, MapPin, Clock, AlertCircle, Activity, Zap, CheckCircle, Lock, AlertTriangle, Database } from 'lucide-react'
import { detectionsApi, Detection } from '../services/api'

interface DetectionDetailModalProps {
  detection: Detection
  onClose: () => void
}

const detectionTypeConfig: Record<string, { label: string; icon: React.ElementType; color: string; bgColor: string; description: string }> = {
  'cloudwatch_logs_insights': {
    label: 'CloudWatch Logs Insights',
    icon: Activity,
    color: 'text-orange-700',
    bgColor: 'bg-orange-100',
    description: 'Query-based detection using CloudWatch Logs Insights'
  },
  'eventbridge_rule': {
    label: 'EventBridge Rule',
    icon: Zap,
    color: 'text-purple-700',
    bgColor: 'bg-purple-100',
    description: 'Event-driven detection using EventBridge rules'
  },
  'guardduty_finding': {
    label: 'GuardDuty Finding',
    icon: Shield,
    color: 'text-red-700',
    bgColor: 'bg-red-100',
    description: 'AWS managed threat detection from GuardDuty'
  },
  'config_rule': {
    label: 'AWS Config Rule',
    icon: CheckCircle,
    color: 'text-green-700',
    bgColor: 'bg-green-100',
    description: 'Compliance-based detection using AWS Config'
  },
  'security_hub': {
    label: 'Security Hub',
    icon: Lock,
    color: 'text-blue-700',
    bgColor: 'bg-blue-100',
    description: 'Aggregated security findings from Security Hub'
  }
}

function getTypeConfig(type: string) {
  return detectionTypeConfig[type] || {
    label: type.replace(/_/g, ' '),
    icon: Database,
    color: 'text-gray-700',
    bgColor: 'bg-gray-100',
    description: 'Detection source'
  }
}

function ConfidenceBadge({ confidence }: { confidence: number }) {
  const percent = Math.round(confidence * 100)
  let bgColor = 'bg-red-100 text-red-800'
  if (confidence >= 0.6) {
    bgColor = 'bg-green-100 text-green-800'
  } else if (confidence >= 0.4) {
    bgColor = 'bg-yellow-100 text-yellow-800'
  }

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${bgColor}`}>
      {percent}%
    </span>
  )
}

export default function DetectionDetailModal({ detection, onClose }: DetectionDetailModalProps) {
  const { data: detectionDetail } = useQuery({
    queryKey: ['detection', detection.id],
    queryFn: () => detectionsApi.get(detection.id),
  })

  const { data: mappingsData, isLoading: mappingsLoading } = useQuery({
    queryKey: ['detection-mappings', detection.id],
    queryFn: () => detectionsApi.getMappings(detection.id),
  })

  const mappings = mappingsData?.mappings ?? []

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black bg-opacity-50 transition-opacity"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative bg-white rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">{detection.name}</h2>
              <div className="flex items-center mt-1">
                {(() => {
                  const config = getTypeConfig(detection.detection_type)
                  const TypeIcon = config.icon
                  return (
                    <span className={`inline-flex items-center px-2.5 py-1 text-xs font-medium rounded-full ${config.bgColor} ${config.color}`}>
                      <TypeIcon className="h-3 w-3 mr-1" />
                      {config.label}
                    </span>
                  )
                })()}
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Content */}
          <div className="p-4 overflow-y-auto max-h-[calc(90vh-140px)]">
            {/* Info Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="flex items-center text-gray-500 text-xs mb-1">
                  <Shield className="h-3 w-3 mr-1" />
                  Status
                </div>
                <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                  detection.status === 'active'
                    ? 'bg-green-100 text-green-800'
                    : 'bg-gray-100 text-gray-800'
                }`}>
                  {detection.status}
                </span>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="flex items-center text-gray-500 text-xs mb-1">
                  <MapPin className="h-3 w-3 mr-1" />
                  Region
                </div>
                <p className="font-medium text-gray-900">{detection.region}</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="flex items-center text-gray-500 text-xs mb-1">
                  <AlertCircle className="h-3 w-3 mr-1" />
                  Mappings
                </div>
                <p className="font-medium text-gray-900">{detection.mapping_count} techniques</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="flex items-center text-gray-500 text-xs mb-1">
                  <Clock className="h-3 w-3 mr-1" />
                  Discovered
                </div>
                <p className="font-medium text-gray-900 text-sm">
                  {new Date(detection.discovered_at).toLocaleDateString()}
                </p>
              </div>
            </div>

            {/* Description */}
            {detectionDetail?.description && (
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Description</h3>
                <p className="text-sm text-gray-600 bg-gray-50 rounded-lg p-3">
                  {detectionDetail.description}
                </p>
              </div>
            )}

            {/* Source ARN */}
            {detectionDetail?.source_arn && (
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Source ARN</h3>
                <code className="text-xs text-gray-600 bg-gray-100 rounded p-2 block overflow-x-auto">
                  {detectionDetail.source_arn}
                </code>
              </div>
            )}

            {/* Event Pattern (for EventBridge rules) */}
            {detectionDetail?.event_pattern && (
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Event Pattern</h3>
                <pre className="text-xs text-gray-600 bg-gray-100 rounded p-3 overflow-x-auto">
                  {JSON.stringify(detectionDetail.event_pattern, null, 2)}
                </pre>
              </div>
            )}

            {/* Query Pattern (for CloudWatch queries) */}
            {detectionDetail?.query_pattern && (
              <div className="mb-6">
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Query Pattern</h3>
                <pre className="text-xs text-gray-600 bg-gray-100 rounded p-3 overflow-x-auto whitespace-pre-wrap">
                  {detectionDetail.query_pattern}
                </pre>
              </div>
            )}

            {/* MITRE Technique Mappings */}
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-3">MITRE ATT&CK Mappings</h3>
              {mappingsLoading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                </div>
              ) : mappings.length > 0 ? (
                <div className="space-y-3">
                  {mappings.map((mapping) => (
                    <div
                      key={mapping.id}
                      className="border rounded-lg p-4 hover:border-blue-300 transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <span className="font-medium text-gray-900">
                              {mapping.technique_id}
                            </span>
                            <span className="text-gray-600">-</span>
                            <span className="text-gray-700">{mapping.technique_name}</span>
                            <ConfidenceBadge confidence={mapping.confidence} />
                          </div>
                          {mapping.rationale && (
                            <p className="mt-2 text-sm text-gray-600">{mapping.rationale}</p>
                          )}
                          {mapping.matched_indicators && mapping.matched_indicators.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1">
                              {mapping.matched_indicators.map((indicator, idx) => (
                                <span
                                  key={idx}
                                  className="px-2 py-0.5 text-xs bg-blue-50 text-blue-700 rounded"
                                >
                                  {indicator}
                                </span>
                              ))}
                            </div>
                          )}
                          <div className="mt-2 text-xs text-gray-400">
                            Mapped via: {mapping.mapping_source}
                          </div>
                        </div>
                        <a
                          href={`https://attack.mitre.org/techniques/${mapping.technique_id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="ml-4 p-2 text-gray-400 hover:text-blue-600 transition-colors"
                          title="View on MITRE ATT&CK"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500 bg-gray-50 rounded-lg">
                  No MITRE technique mappings found for this detection
                </div>
              )}
            </div>
          </div>

          {/* Footer */}
          <div className="border-t p-4 bg-gray-50 flex justify-end">
            <button onClick={onClose} className="btn-secondary">
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
