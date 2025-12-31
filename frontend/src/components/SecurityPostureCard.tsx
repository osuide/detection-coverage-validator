/**
 * Security Posture Card Component.
 *
 * Displays detection effectiveness for a single Security Hub standard,
 * showing actual compliance findings (PASSED/FAILED) from Security Hub.
 *
 * This answers the question: "What violations did our detections find?"
 */

import { useState } from 'react'
import {
  Shield,
  CheckCircle,
  XCircle,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
} from 'lucide-react'
import { DetectionEffectiveness, FailingControlItem } from '../services/api'

// Human-readable names for Security Hub standards
// Note: "AWS NIST 800-53" differentiates from the compliance framework "NIST 800-53 Rev 5"
const STANDARD_DISPLAY_NAMES: Record<string, string> = {
  fsbp: 'AWS Foundational Security Best Practices',
  cis: 'CIS AWS Foundations Benchmark',
  pci: 'PCI DSS',
  nist: 'AWS NIST 800-53',
  nist171: 'AWS NIST 800-171',
  tagging: 'AWS Resource Tagging Standard',
}

// AWS Console URLs for Security Hub standards
const STANDARD_CONSOLE_URLS: Record<string, string> = {
  fsbp: 'standards/aws-foundational-security-best-practices/v/1.0.0',
  cis: 'standards/cis-aws-foundations-benchmark/v/1.2.0',
  pci: 'standards/pci-dss/v/3.2.1',
  nist: 'standards/nist-800-53/v/5.0.0',
  nist171: 'standards/nist-sp-800-171/v/2.0.0',
  tagging: 'standards/aws-resource-tagging-standard/v/1.0.0',
}

const SEVERITY_COLOURS: Record<string, string> = {
  CRITICAL: 'text-red-500 bg-red-500/20',
  HIGH: 'text-orange-500 bg-orange-500/20',
  MEDIUM: 'text-yellow-500 bg-yellow-500/20',
  LOW: 'text-blue-500 bg-blue-500/20',
  INFORMATIONAL: 'text-gray-500 bg-gray-500/20',
}

const SEVERITY_DOT_COLOURS: Record<string, string> = {
  CRITICAL: 'text-red-500',
  HIGH: 'text-orange-500',
  MEDIUM: 'text-yellow-500',
  LOW: 'text-blue-500',
  INFORMATIONAL: 'text-gray-500',
}

interface SecurityPostureCardProps {
  standardId: string
  standardName: string
  effectiveness: DetectionEffectiveness
  region: string
  /** Show expandable failing controls list (for Compliance page) */
  showFailingControls?: boolean
  /** Number of items per page for failing controls */
  pageSize?: number
  /** Total controls enabled (for inline display) */
  enabledControls?: number
  /** Total controls available */
  totalControls?: number
}

export function SecurityPostureCard({
  standardId,
  standardName,
  effectiveness,
  region,
  showFailingControls = false,
  pageSize = 10,
  enabledControls,
  totalControls: totalControlsAvailable,
}: SecurityPostureCardProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [currentPage, setCurrentPage] = useState(1)

  const displayName = STANDARD_DISPLAY_NAMES[standardId] || standardName
  const consoleUrlPath = STANDARD_CONSOLE_URLS[standardId] || ''

  const {
    total_controls,
    passed_count,
    failed_count,
    compliance_percent,
    by_severity,
    all_failing_controls,
  } = effectiveness

  // Calculate pagination (only when showFailingControls is true)
  const totalPages = showFailingControls ? Math.ceil((all_failing_controls?.length || 0) / pageSize) : 0
  const paginatedControls = showFailingControls && all_failing_controls
    ? all_failing_controls.slice((currentPage - 1) * pageSize, currentPage * pageSize)
    : []

  // Determine compliance status colour
  const getComplianceColour = (percent: number) => {
    if (percent >= 80) return 'text-green-400'
    if (percent >= 50) return 'text-yellow-400'
    return 'text-red-400'
  }

  // Build Security Hub console URL
  const securityHubUrl = consoleUrlPath
    ? `https://${region}.console.aws.amazon.com/securityhub/home?region=${region}#/${consoleUrlPath}`
    : `https://${region}.console.aws.amazon.com/securityhub/home?region=${region}`

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700">
      {/* Card Content */}
      <div className="p-4">
        {/* Header with title and controls count */}
        <div className="flex items-start justify-between gap-2 mb-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-blue-400 flex-shrink-0" />
              <h3 className="text-sm font-semibold text-white truncate" title={displayName}>
                {displayName}
              </h3>
            </div>
            {/* Inline coverage note */}
            {enabledControls !== undefined && totalControlsAvailable !== undefined && (
              <p className="text-xs text-gray-500 mt-1 ml-7">
                Monitoring {enabledControls} of {totalControlsAvailable} controls
              </p>
            )}
          </div>
          <a
            href={securityHubUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-gray-400 hover:text-blue-400 transition-colors flex-shrink-0"
            title="View in Security Hub"
          >
            <ExternalLink className="h-4 w-4" />
          </a>
        </div>

        {/* Main stats row - horizontal layout for full width */}
        <div className="flex flex-wrap items-center gap-6 mt-2">
          {/* Compliance percentage - prominent */}
          <div className="flex items-center gap-3">
            <div className="relative w-14 h-14">
              <svg className="w-14 h-14 -rotate-90" viewBox="0 0 56 56">
                <circle
                  cx="28" cy="28" r="24"
                  fill="none"
                  stroke="#374151"
                  strokeWidth="4"
                />
                <circle
                  cx="28" cy="28" r="24"
                  fill="none"
                  stroke={compliance_percent >= 80 ? '#22c55e' : compliance_percent >= 50 ? '#eab308' : '#ef4444'}
                  strokeWidth="4"
                  strokeLinecap="round"
                  strokeDasharray={`${(compliance_percent / 100) * 150.8} 150.8`}
                />
              </svg>
              <span className={`absolute inset-0 flex items-center justify-center text-sm font-bold ${getComplianceColour(compliance_percent)}`}>
                {compliance_percent}%
              </span>
            </div>
            <span className="text-xs text-gray-400">Compliance</span>
          </div>

          {/* Divider */}
          <div className="h-10 w-px bg-gray-700 hidden sm:block" />

          {/* Pass/Fail stats - inline */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              <span className="text-lg font-bold text-green-400">{passed_count}</span>
              <span className="text-xs text-gray-500">passed</span>
            </div>
            <div className="flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-400" />
              <span className="text-lg font-bold text-red-400">{failed_count}</span>
              <span className="text-xs text-gray-500">failed</span>
            </div>
            <div className="text-xs text-gray-500">
              of {total_controls} controls
            </div>
          </div>

          {/* Divider */}
          {failed_count > 0 && <div className="h-10 w-px bg-gray-700 hidden lg:block" />}

          {/* Severity badges - inline */}
          {failed_count > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              {by_severity.CRITICAL > 0 && (
                <span className={`text-xs px-2 py-1 rounded-full ${SEVERITY_COLOURS.CRITICAL}`}>
                  {by_severity.CRITICAL} Critical
                </span>
              )}
              {by_severity.HIGH > 0 && (
                <span className={`text-xs px-2 py-1 rounded-full ${SEVERITY_COLOURS.HIGH}`}>
                  {by_severity.HIGH} High
                </span>
              )}
              {by_severity.MEDIUM > 0 && (
                <span className={`text-xs px-2 py-1 rounded-full ${SEVERITY_COLOURS.MEDIUM}`}>
                  {by_severity.MEDIUM} Medium
                </span>
              )}
              {by_severity.LOW > 0 && (
                <span className={`text-xs px-2 py-1 rounded-full ${SEVERITY_COLOURS.LOW}`}>
                  {by_severity.LOW} Low
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Expandable Failing Controls List (only when showFailingControls is true) */}
      {showFailingControls && failed_count > 0 && (
        <div className="border-t border-gray-700">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="w-full px-4 py-2 flex items-center justify-between text-sm text-gray-400 hover:bg-gray-700/50 transition-colors"
          >
            <span className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-500" />
              View Failing Controls ({failed_count})
            </span>
            {isExpanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </button>

          {isExpanded && (
            <div className="border-t border-gray-700">
              {/* Controls List */}
              <div className="max-h-80 overflow-y-auto">
                {paginatedControls.map((control: FailingControlItem) => (
                  <div
                    key={control.control_id}
                    className="px-4 py-2 border-b border-gray-700 last:border-b-0 hover:bg-gray-700/30"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={SEVERITY_DOT_COLOURS[control.severity]}>●</span>
                          <span className="text-xs font-mono text-gray-300">
                            {control.control_id}
                          </span>
                        </div>
                        <p className="text-xs text-gray-400 truncate mt-0.5" title={control.title}>
                          {control.title}
                        </p>
                      </div>
                      <div className="text-right shrink-0">
                        <span className="text-xs text-red-400">{control.failed_count} failed</span>
                        {control.passed_count > 0 && (
                          <span className="text-xs text-gray-500 ml-2">
                            {control.passed_count} passed
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="px-4 py-2 border-t border-gray-700 flex items-center justify-between">
                  <span className="text-xs text-gray-500">
                    Page {currentPage} of {totalPages}
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      className="px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-600"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages}
                      className="px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-600"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/**
 * Empty state component when no Security Hub data is available.
 */
export function SecurityPostureEmptyState() {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 text-center">
      <Shield className="h-8 w-8 text-gray-600 mx-auto mb-2" />
      <h3 className="text-sm font-medium text-gray-400 mb-1">No Security Posture Data</h3>
      <p className="text-xs text-gray-500">
        Run a scan with Security Hub enabled to see compliance findings.
      </p>
    </div>
  )
}
