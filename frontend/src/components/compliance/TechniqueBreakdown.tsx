/**
 * Technique Breakdown Component.
 *
 * Displays detailed technique-level coverage for a compliance control.
 * Shows which techniques are covered vs. uncovered and what detections
 * provide the coverage.
 */

import { Link } from 'react-router-dom'
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  FileCode,
  ExternalLink,
  Shield,
  CheckCheck,
} from 'lucide-react'
import { TechniqueCoverageDetail, DetectionSummary, AcknowledgedGapInfo } from '../../services/complianceApi'

interface TechniqueBreakdownProps {
  techniques: TechniqueCoverageDetail[]
  rationale: string
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

function getStatusBadgeStyle(status: string) {
  switch (status) {
    case 'covered':
      return 'bg-green-900/50 text-green-300 border-green-700'
    case 'partial':
      return 'bg-yellow-900/50 text-yellow-300 border-yellow-700'
    case 'uncovered':
      return 'bg-red-900/50 text-red-300 border-red-700'
    default:
      return 'bg-gray-700 text-gray-300 border-gray-600'
  }
}

function DetectionItem({ detection }: { detection: DetectionSummary }) {
  // Format the source name nicely
  const formatSource = (source: string) => {
    return source
      .replace('aws_', 'AWS ')
      .replace('gcp_', 'GCP ')
      .replace('_', ' ')
      .split(' ')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  }

  return (
    <div className="flex items-center gap-2 text-xs text-gray-400 pl-6 py-1">
      <span className="text-gray-500">└─</span>
      <span className="text-gray-300">{detection.name}</span>
      <span className="text-gray-500">({formatSource(detection.source)})</span>
      <span className="text-green-400">{Math.round(detection.confidence * 100)}%</span>
    </div>
  )
}

function AcknowledgedGapIndicator({
  acknowledged_gap,
}: {
  acknowledged_gap?: AcknowledgedGapInfo | null
}) {
  if (!acknowledged_gap) {
    return null
  }

  const isRiskAccepted = acknowledged_gap.status === 'risk_accepted'
  const statusLabel = isRiskAccepted ? 'Risk Accepted' : 'Acknowledged'
  const bgColor = isRiskAccepted ? 'bg-purple-900/50' : 'bg-blue-900/50'
  const borderColor = isRiskAccepted ? 'border-purple-700/50' : 'border-blue-700/50'
  const textColor = isRiskAccepted ? 'text-purple-300' : 'text-blue-300'

  return (
    <div className={`mx-3 mb-2 p-2 ${bgColor} border ${borderColor} rounded-lg`}>
      <div className="flex items-center gap-2">
        <CheckCheck className={`w-4 h-4 ${textColor}`} />
        <span className={`text-xs font-medium ${textColor}`}>
          MITRE Gap {statusLabel}
        </span>
      </div>
      {acknowledged_gap.reason && (
        <p className="text-xs text-gray-400 mt-1 pl-6">
          {acknowledged_gap.reason}
        </p>
      )}
      {acknowledged_gap.accepted_by && (
        <p className="text-xs text-gray-500 mt-1 pl-6">
          by {acknowledged_gap.accepted_by}
          {acknowledged_gap.accepted_at && (
            <span> on {new Date(acknowledged_gap.accepted_at).toLocaleDateString()}</span>
          )}
        </p>
      )}
    </div>
  )
}

function ServiceCoverageIndicator({
  service_coverage,
}: {
  service_coverage?: TechniqueCoverageDetail['service_coverage']
}) {
  if (!service_coverage || service_coverage.in_scope_services.length === 0) {
    return null
  }

  const { covered_services, uncovered_services, coverage_percent } = service_coverage

  return (
    <div className="mt-2 mx-3 mb-2 px-3 py-2 bg-gray-900/50 rounded-md border border-gray-700/50">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-gray-400">Service Coverage</span>
        <span
          className={`text-xs font-medium ${
            coverage_percent >= 80
              ? 'text-green-400'
              : coverage_percent >= 50
                ? 'text-yellow-400'
                : 'text-red-400'
          }`}
        >
          {Math.round(coverage_percent)}%
        </span>
      </div>
      <div className="flex flex-wrap gap-1">
        {covered_services.map((service) => (
          <span
            key={service}
            className="inline-flex items-center gap-1 px-2 py-0.5 text-xs bg-green-900/50 text-green-300 border border-green-700/50 rounded-sm"
          >
            <CheckCircle className="w-3 h-3" />
            {service}
          </span>
        ))}
        {uncovered_services.map((service) => (
          <span
            key={service}
            className="inline-flex items-center gap-1 px-2 py-0.5 text-xs bg-red-900/50 text-red-300 border border-red-700/50 rounded-sm"
          >
            <XCircle className="w-3 h-3" />
            {service}
          </span>
        ))}
      </div>
    </div>
  )
}

function TechniqueRow({ technique }: { technique: TechniqueCoverageDetail }) {
  const isUncovered = technique.status === 'uncovered'

  return (
    <div className="border-b border-gray-700/50 last:border-0">
      {/* Technique header */}
      <div className="flex items-center justify-between py-2 px-3">
        <div className="flex items-center gap-3">
          {getStatusIcon(technique.status)}
          <span className="text-sm font-mono text-blue-400">
            {technique.technique_id}
          </span>
          <span className="text-sm text-gray-300">{technique.technique_name}</span>
        </div>
        <div className="flex items-center gap-2">
          {technique.confidence !== null && technique.confidence > 0 && (
            <span
              className={`px-2 py-0.5 text-xs rounded border ${getStatusBadgeStyle(
                technique.status
              )}`}
            >
              {Math.round(technique.confidence * 100)}%
            </span>
          )}
          {isUncovered && (
            <>
              {technique.has_template ? (
                <Link
                  to={`/techniques/${technique.technique_id}`}
                  className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium bg-green-900/50 text-green-300 border border-green-700 rounded-sm hover:bg-green-800/50 transition-colors"
                >
                  <FileCode className="w-3 h-3" />
                  View Template
                </Link>
              ) : (
                <a
                  href={`https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium bg-gray-700 text-gray-400 border border-gray-600 rounded-sm hover:bg-gray-600 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" />
                  MITRE ATT&CK
                </a>
              )}
            </>
          )}
        </div>
      </div>

      {/* Service coverage indicator */}
      <ServiceCoverageIndicator service_coverage={technique.service_coverage} />

      {/* Acknowledged gap indicator */}
      <AcknowledgedGapIndicator acknowledged_gap={technique.acknowledged_gap} />

      {/* Detection details for covered techniques */}
      {technique.detections.length > 0 && (
        <div className="pb-2">
          {technique.detections.map((detection) => (
            <DetectionItem key={detection.id} detection={detection} />
          ))}
        </div>
      )}

      {/* Show guidance for uncovered techniques */}
      {isUncovered && technique.detections.length === 0 && (
        <div className="flex items-center gap-2 text-xs text-gray-500 pl-6 pb-2">
          <span className="text-gray-500">└─</span>
          <span className="italic">No detections found</span>
        </div>
      )}
    </div>
  )
}

export function TechniqueBreakdown({ techniques, rationale }: TechniqueBreakdownProps) {
  if (techniques.length === 0) {
    return (
      <div className="text-sm text-gray-400 italic py-4 text-center">
        No MITRE techniques mapped to this control
      </div>
    )
  }

  return (
    <div className="bg-gray-800/50 rounded-lg overflow-hidden">
      {/* Rationale banner */}
      <div className="px-4 py-3 bg-gray-700/30 border-b border-gray-700">
        <p className="text-sm text-gray-300">{rationale}</p>
      </div>

      {/* Technique list */}
      <div className="divide-y divide-gray-700/50">
        {techniques.map((technique) => (
          <TechniqueRow key={technique.technique_id} technique={technique} />
        ))}
      </div>
    </div>
  )
}

export default TechniqueBreakdown
