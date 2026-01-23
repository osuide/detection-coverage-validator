import { useQuery } from '@tanstack/react-query'
import { X, Copy, Check, Terminal, FileCode, Cloud, AlertTriangle, Shield, BookOpen } from 'lucide-react'
import { useState, useEffect } from 'react'
import { recommendationsApi, StrategyDetail } from '../services/api'

interface StrategyDetailModalProps {
  techniqueId: string
  strategyId: string
  strategyName: string
  onClose: () => void
}

export default function StrategyDetailModal({
  techniqueId,
  strategyId,
  strategyName,
  onClose,
}: StrategyDetailModalProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'query' | 'cloudformation' | 'terraform' | 'gcp_query' | 'gcp_terraform' | 'azure_query' | 'azure_terraform' | 'response'>('overview')
  const [copiedField, setCopiedField] = useState<string | null>(null)

  // Reset tab to overview when strategy changes to prevent showing blank content
  useEffect(() => {
    setActiveTab('overview')
  }, [techniqueId, strategyId])

  const { data: details, isLoading, error } = useQuery({
    queryKey: ['strategyDetail', techniqueId, strategyId],
    queryFn: () => recommendationsApi.getStrategyDetails(techniqueId, strategyId),
  })

  const copyToClipboard = async (text: string, field: string) => {
    await navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: BookOpen },
    // AWS tabs
    ...(details?.query ? [{ id: 'query', label: 'AWS Query', icon: Terminal }] : []),
    ...(details?.cloudformation_template ? [{ id: 'cloudformation', label: 'CloudFormation', icon: Cloud }] : []),
    ...(details?.terraform_template ? [{ id: 'terraform', label: 'AWS Terraform', icon: FileCode }] : []),
    // GCP tabs
    ...(details?.gcp_logging_query ? [{ id: 'gcp_query', label: 'GCP Query', icon: Terminal }] : []),
    ...(details?.gcp_terraform_template ? [{ id: 'gcp_terraform', label: 'GCP Terraform', icon: FileCode }] : []),
    // Azure tabs
    ...(details?.azure_kql_query ? [{ id: 'azure_query', label: 'Azure KQL', icon: Terminal }] : []),
    ...(details?.azure_terraform_template ? [{ id: 'azure_terraform', label: 'Azure Terraform', icon: FileCode }] : []),
    { id: 'response', label: 'Response', icon: Shield },
  ] as const

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        {/* Backdrop */}
        <div
          className="fixed inset-0 bg-black/50 transition-opacity"
          onClick={onClose}
        />

        {/* Modal */}
        <div className="relative bg-white rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 bg-gray-50">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">{strategyName}</h2>
              <p className="text-sm text-gray-500">
                {techniqueId} &bull; {details?.detection_type} via {details?.azure_service || details?.gcp_service || details?.aws_service || 'n/a'}
                {details?.cloud_provider && (
                  <span className={`ml-2 px-1.5 py-0.5 text-xs rounded ${
                    details.cloud_provider === 'gcp'
                      ? 'bg-blue-100 text-blue-700'
                      : details.cloud_provider === 'azure'
                        ? 'bg-cyan-100 text-cyan-700'
                        : 'bg-orange-100 text-orange-700'
                  }`}>
                    {details.cloud_provider.toUpperCase()}
                  </span>
                )}
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-200 rounded-lg transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-gray-200 px-6 bg-white">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="p-6 overflow-y-auto max-h-[60vh]">
            {isLoading ? (
              <div className="flex items-center justify-center h-48">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
              </div>
            ) : error ? (
              <div className="text-center py-8">
                <AlertTriangle className="mx-auto h-12 w-12 text-red-400" />
                <p className="mt-2 text-gray-600">Failed to load strategy details</p>
              </div>
            ) : details ? (
              <>
                {activeTab === 'overview' && (
                  <OverviewTab details={details} />
                )}
                {activeTab === 'query' && details.query && (
                  <CodeTab
                    title="AWS CloudWatch Logs Insights Query"
                    code={details.query}
                    language="sql"
                    onCopy={() => copyToClipboard(details.query!, 'query')}
                    copied={copiedField === 'query'}
                  />
                )}
                {activeTab === 'cloudformation' && details.cloudformation_template && (
                  <CodeTab
                    title="CloudFormation Template"
                    code={details.cloudformation_template}
                    language="yaml"
                    onCopy={() => copyToClipboard(details.cloudformation_template!, 'cfn')}
                    copied={copiedField === 'cfn'}
                  />
                )}
                {activeTab === 'terraform' && details.terraform_template && (
                  <CodeTab
                    title="AWS Terraform Configuration"
                    code={details.terraform_template}
                    language="hcl"
                    onCopy={() => copyToClipboard(details.terraform_template!, 'tf')}
                    copied={copiedField === 'tf'}
                  />
                )}
                {activeTab === 'gcp_query' && details.gcp_logging_query && (
                  <CodeTab
                    title="GCP Cloud Logging Query"
                    code={details.gcp_logging_query}
                    language="sql"
                    onCopy={() => copyToClipboard(details.gcp_logging_query!, 'gcp_query')}
                    copied={copiedField === 'gcp_query'}
                  />
                )}
                {activeTab === 'gcp_terraform' && details.gcp_terraform_template && (
                  <CodeTab
                    title="GCP Terraform Configuration"
                    code={details.gcp_terraform_template}
                    language="hcl"
                    onCopy={() => copyToClipboard(details.gcp_terraform_template!, 'gcp_tf')}
                    copied={copiedField === 'gcp_tf'}
                  />
                )}
                {activeTab === 'azure_query' && details.azure_kql_query && (
                  <CodeTab
                    title="Azure Log Analytics KQL Query"
                    code={details.azure_kql_query}
                    language="sql"
                    onCopy={() => copyToClipboard(details.azure_kql_query!, 'azure_query')}
                    copied={copiedField === 'azure_query'}
                  />
                )}
                {activeTab === 'azure_terraform' && details.azure_terraform_template && (
                  <CodeTab
                    title="Azure Terraform Configuration"
                    code={details.azure_terraform_template}
                    language="hcl"
                    onCopy={() => copyToClipboard(details.azure_terraform_template!, 'azure_tf')}
                    copied={copiedField === 'azure_tf'}
                  />
                )}
                {activeTab === 'response' && (
                  <ResponseTab details={details} />
                )}
              </>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  )
}

function OverviewTab({ details }: { details: StrategyDetail }) {
  return (
    <div className="space-y-6">
      {/* Description */}
      <div>
        <h3 className="text-sm font-medium text-gray-700 mb-2">Description</h3>
        <p className="text-gray-600">{details.description}</p>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Effort" value={details.implementation_effort} />
        <MetricCard label="Time" value={details.implementation_time} />
        <MetricCard label="Coverage" value={details.detection_coverage} />
        <MetricCard label="False Positives" value={details.estimated_false_positive_rate} />
      </div>

      {/* Prerequisites */}
      {details.prerequisites.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-2">Prerequisites</h3>
          <ul className="list-disc list-inside text-gray-600 space-y-1">
            {details.prerequisites.map((prereq, idx) => (
              <li key={idx}>{prereq}</li>
            ))}
          </ul>
        </div>
      )}

      {/* GuardDuty Finding Types */}
      {details.guardduty_finding_types && details.guardduty_finding_types.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-gray-700 mb-2">GuardDuty Finding Types</h3>
          <div className="flex flex-wrap gap-2">
            {details.guardduty_finding_types.map((finding) => (
              <code key={finding} className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded-sm">
                {finding}
              </code>
            ))}
          </div>
        </div>
      )}

      {/* Alert Configuration */}
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
        <h3 className="text-sm font-medium text-amber-900 mb-2">Alert Configuration</h3>
        <p className="text-xs text-amber-700 mb-3">
          These alert settings are pre-configured in the Terraform/CloudFormation templates above.
          Deploy the template to create this detection with these alert settings already applied.
        </p>
        <div className="space-y-2 text-sm text-amber-900">
          <p><span className="font-medium">Severity:</span> {details.alert_severity}</p>
          <p><span className="font-medium">Title:</span> {details.alert_title}</p>
          <p><span className="font-medium">Description Template:</span></p>
          <p className="text-amber-900 bg-amber-100 p-2 rounded-sm text-xs font-mono">
            {details.alert_description_template}
          </p>
        </div>
      </div>

      {/* False Positive Tuning */}
      <div>
        <h3 className="text-sm font-medium text-gray-700 mb-2">False Positive Tuning</h3>
        <p className="text-gray-600">{details.false_positive_tuning}</p>
      </div>

      {/* Evasion Considerations */}
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <h3 className="text-sm font-medium text-red-900 mb-2">Evasion Considerations</h3>
        <p className="text-red-900 text-sm">{details.evasion_considerations}</p>
      </div>
    </div>
  )
}

function CodeTab({
  title,
  code,
  language,
  onCopy,
  copied
}: {
  title: string
  code: string
  language: string
  onCopy: () => void
  copied: boolean
}) {
  return (
    <div className="space-y-4">
      {/* Review Warning */}
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-amber-700 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-medium text-amber-900">Review Before Use</p>
          <p className="text-amber-900 mt-1">
            This template is provided as a starting point and should be reviewed and customised
            for your specific environment before deployment. Ensure it aligns with your
            organisation's security policies and infrastructure requirements.
          </p>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-700">{title}</h3>
        <button
          onClick={onCopy}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          {copied ? (
            <>
              <Check className="h-4 w-4" />
              Copied!
            </>
          ) : (
            <>
              <Copy className="h-4 w-4" />
              Copy to Clipboard
            </>
          )}
        </button>
      </div>
      <div className="relative">
        <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm font-mono">
          <code>{code}</code>
        </pre>
        <span className="absolute top-2 right-2 text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded-sm">
          {language}
        </span>
      </div>
    </div>
  )
}

function ResponseTab({ details }: { details: StrategyDetail }) {
  return (
    <div className="space-y-6">
      {/* Investigation Steps */}
      <div>
        <h3 className="text-sm font-medium text-gray-700 mb-3">Investigation Steps</h3>
        <ol className="space-y-2">
          {details.investigation_steps.map((step, idx) => (
            <li key={idx} className="flex items-start gap-3">
              <span className="shrink-0 w-6 h-6 bg-blue-100 text-blue-900 rounded-full flex items-center justify-center text-xs font-medium">
                {idx + 1}
              </span>
              <span className="text-gray-600">{step}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Containment Actions */}
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <h3 className="text-sm font-medium text-red-900 mb-3">Containment Actions</h3>
        <ol className="space-y-2">
          {details.containment_actions.map((action, idx) => (
            <li key={idx} className="flex items-start gap-3">
              <span className="shrink-0 w-6 h-6 bg-red-200 text-red-900 rounded-full flex items-center justify-center text-xs font-medium">
                {idx + 1}
              </span>
              <span className="text-red-900">{action}</span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  )
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-gray-50 rounded-lg p-3">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className="text-sm font-medium text-gray-900 capitalize">{value}</p>
    </div>
  )
}
