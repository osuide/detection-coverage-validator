/**
 * Technique Detail Page.
 *
 * Displays remediation templates and detection strategies for a MITRE ATT&CK technique.
 * Shows cloud-specific implementation guidance (AWS/GCP) with IaC templates.
 */

import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Clock,
  ExternalLink,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Zap,
  Users,
  Target,
  TrendingUp,
  FileCode,
  Search,
  Wrench,
  Lock,
} from 'lucide-react'
import api from '../services/api'

// API types
interface Campaign {
  name: string
  year: number
  description: string
  reference_url?: string
}

interface ThreatContext {
  description: string
  attacker_goal: string
  why_technique: string[]
  known_threat_actors: string[]
  recent_campaigns: Campaign[]
  prevalence: string
  trend: string
  severity_score: number
  severity_reasoning: string
  business_impact: string[]
  typical_attack_phase: string
  often_precedes: string[]
  often_follows: string[]
}

interface DetectionImplementation {
  query?: string
  gcp_logging_query?: string
  guardduty_finding_types?: string[]
  cloudformation_template?: string
  terraform_template?: string
  gcp_terraform_template?: string
  alert_severity: string
  alert_title: string
  alert_description_template: string
  investigation_steps: string[]
  containment_actions: string[]
}

interface DetectionStrategy {
  strategy_id: string
  name: string
  description: string
  detection_type: string
  aws_service?: string
  gcp_service?: string
  cloud_provider: string
  implementation: DetectionImplementation
  estimated_false_positive_rate: string
  false_positive_tuning?: string
  detection_coverage?: string
  evasion_considerations?: string
  implementation_effort: string
  implementation_time?: string
  estimated_monthly_cost?: string
  prerequisites: string[]
}

interface TechniqueDetail {
  technique_id: string
  technique_name: string
  tactic_ids: string[]
  tactic_names: string[]
  mitre_url: string
  threat_context: ThreatContext
  detection_strategies: DetectionStrategy[]
  recommended_order: string[]
  total_effort_hours: number
  coverage_improvement: string
}

// Code block component with copy button
function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="relative">
      <div className="absolute right-2 top-2">
        <button
          onClick={handleCopy}
          className="p-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
          title="Copy to clipboard"
        >
          {copied ? (
            <Check className="w-4 h-4 text-green-400" />
          ) : (
            <Copy className="w-4 h-4" />
          )}
        </button>
      </div>
      <div className="text-xs text-gray-500 mb-1">{language}</div>
      <pre className="bg-gray-900 rounded-lg p-4 overflow-x-auto text-sm text-gray-300 font-mono">
        <code>{code}</code>
      </pre>
    </div>
  )
}

// Detection strategy card component
function StrategyCard({ strategy, defaultOpen }: { strategy: DetectionStrategy; defaultOpen: boolean }) {
  const [isOpen, setIsOpen] = useState(defaultOpen)
  const [activeTab, setActiveTab] = useState<'cloudformation' | 'terraform' | 'gcp'>('terraform')
  const [templatesExpanded, setTemplatesExpanded] = useState(false)

  const isAWS = strategy.cloud_provider === 'aws'

  const getEffortBadge = (effort: string) => {
    const styles: Record<string, string> = {
      low: 'bg-green-900/50 text-green-300 border-green-700',
      medium: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
      high: 'bg-red-900/50 text-red-300 border-red-700',
    }
    return styles[effort] || 'bg-gray-700 text-gray-300 border-gray-600'
  }

  const getFPRBadge = (fpr: string) => {
    const styles: Record<string, string> = {
      low: 'bg-green-900/50 text-green-300 border-green-700',
      medium: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
      high: 'bg-red-900/50 text-red-300 border-red-700',
    }
    return styles[fpr] || 'bg-gray-700 text-gray-300 border-gray-600'
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-4">
          <span
            className={`px-2 py-1 text-xs font-medium rounded border ${
              isAWS
                ? 'bg-orange-900/50 text-orange-300 border-orange-700'
                : 'bg-blue-900/50 text-blue-300 border-blue-700'
            }`}
          >
            {isAWS ? 'AWS' : 'GCP'}
          </span>
          <div className="text-left">
            <h4 className="font-medium text-white">{strategy.name}</h4>
            <p className="text-sm text-gray-400">{strategy.detection_type.replace(/_/g, ' ')}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`px-2 py-0.5 text-xs font-medium rounded border ${getEffortBadge(strategy.implementation_effort)}`}>
            {strategy.implementation_effort} effort
          </span>
          <span className={`px-2 py-0.5 text-xs font-medium rounded border ${getFPRBadge(strategy.estimated_false_positive_rate)}`}>
            {strategy.estimated_false_positive_rate} FP rate
          </span>
          {isOpen ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
      </button>

      {/* Expanded content */}
      {isOpen && (
        <div className="px-6 pb-6 border-t border-gray-700 pt-4 space-y-6">
          {/* Description */}
          <p className="text-gray-300">{strategy.description}</p>

          {/* Quick stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {strategy.implementation_time && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">Setup Time</div>
                <div className="font-medium text-white">{strategy.implementation_time}</div>
              </div>
            )}
            {strategy.estimated_monthly_cost && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">Est. Monthly Cost</div>
                <div className="font-medium text-white">{strategy.estimated_monthly_cost}</div>
              </div>
            )}
            {strategy.detection_coverage && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">Coverage</div>
                <div className="font-medium text-white text-sm">{strategy.detection_coverage}</div>
              </div>
            )}
            {strategy.aws_service && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">AWS Service</div>
                <div className="font-medium text-orange-400">{strategy.aws_service}</div>
              </div>
            )}
            {strategy.gcp_service && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">GCP Service</div>
                <div className="font-medium text-blue-400">{strategy.gcp_service}</div>
              </div>
            )}
          </div>

          {/* Prerequisites */}
          {strategy.prerequisites.length > 0 && (
            <div>
              <h5 className="text-sm font-medium text-gray-300 mb-2">Prerequisites</h5>
              <ul className="list-disc list-inside text-sm text-gray-400 space-y-1">
                {strategy.prerequisites.map((prereq, i) => (
                  <li key={i}>{prereq}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Implementation Templates - Collapsible */}
          <div className="border border-gray-700 rounded-lg overflow-hidden">
            <button
              onClick={() => setTemplatesExpanded(!templatesExpanded)}
              className="w-full px-4 py-3 flex items-center justify-between bg-gray-700/30 hover:bg-gray-700/50 transition-colors"
            >
              <h5 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <FileCode className="w-4 h-4" />
                Implementation Templates
                <span className="text-xs text-gray-500">
                  ({[
                    strategy.implementation.terraform_template && 'Terraform',
                    strategy.implementation.cloudformation_template && 'CloudFormation',
                    strategy.implementation.gcp_terraform_template && 'GCP Terraform',
                  ].filter(Boolean).join(', ')})
                </span>
              </h5>
              {templatesExpanded ? (
                <ChevronDown className="w-4 h-4 text-gray-400" />
              ) : (
                <ChevronRight className="w-4 h-4 text-gray-400" />
              )}
            </button>

            {templatesExpanded && (
              <div className="p-4 border-t border-gray-700">
                {/* Tab selector */}
                <div className="flex gap-2 mb-4">
                  {strategy.implementation.terraform_template && (
                    <button
                      onClick={() => setActiveTab('terraform')}
                      className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                        activeTab === 'terraform'
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      Terraform (AWS)
                    </button>
                  )}
                  {strategy.implementation.cloudformation_template && (
                    <button
                      onClick={() => setActiveTab('cloudformation')}
                      className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                        activeTab === 'cloudformation'
                          ? 'bg-orange-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      CloudFormation
                    </button>
                  )}
                  {strategy.implementation.gcp_terraform_template && (
                    <button
                      onClick={() => setActiveTab('gcp')}
                      className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                        activeTab === 'gcp'
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      Terraform (GCP)
                    </button>
                  )}
                </div>

                {/* Template content */}
                {activeTab === 'terraform' && strategy.implementation.terraform_template && (
                  <CodeBlock code={strategy.implementation.terraform_template} language="Terraform (HCL)" />
                )}
                {activeTab === 'cloudformation' && strategy.implementation.cloudformation_template && (
                  <CodeBlock code={strategy.implementation.cloudformation_template} language="CloudFormation (YAML)" />
                )}
                {activeTab === 'gcp' && strategy.implementation.gcp_terraform_template && (
                  <CodeBlock code={strategy.implementation.gcp_terraform_template} language="Terraform (GCP)" />
                )}
              </div>
            )}
          </div>

          {/* Query if available */}
          {strategy.implementation.query && (
            <div>
              <h5 className="text-sm font-medium text-gray-300 mb-2 flex items-center gap-2">
                <Search className="w-4 h-4" />
                CloudWatch Logs Insights Query
              </h5>
              <CodeBlock code={strategy.implementation.query} language="CloudWatch Logs Insights" />
            </div>
          )}

          {strategy.implementation.gcp_logging_query && (
            <div>
              <h5 className="text-sm font-medium text-gray-300 mb-2 flex items-center gap-2">
                <Search className="w-4 h-4" />
                Cloud Logging Query
              </h5>
              <CodeBlock code={strategy.implementation.gcp_logging_query} language="Cloud Logging" />
            </div>
          )}

          {/* Investigation Steps */}
          <div>
            <h5 className="text-sm font-medium text-gray-300 mb-2 flex items-center gap-2">
              <Search className="w-4 h-4" />
              Investigation Steps
            </h5>
            <ol className="list-decimal list-inside text-sm text-gray-400 space-y-1">
              {strategy.implementation.investigation_steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          </div>

          {/* Containment Actions */}
          <div>
            <h5 className="text-sm font-medium text-gray-300 mb-2 flex items-center gap-2">
              <Lock className="w-4 h-4" />
              Containment Actions
            </h5>
            <ol className="list-decimal list-inside text-sm text-gray-400 space-y-1">
              {strategy.implementation.containment_actions.map((action, i) => (
                <li key={i}>{action}</li>
              ))}
            </ol>
          </div>

          {/* False positive tuning */}
          {strategy.false_positive_tuning && (
            <div className="bg-yellow-900/20 border border-yellow-800 rounded-lg p-4">
              <h5 className="text-sm font-medium text-yellow-300 mb-2 flex items-center gap-2">
                <Wrench className="w-4 h-4" />
                False Positive Tuning
              </h5>
              <p className="text-sm text-gray-300">{strategy.false_positive_tuning}</p>
            </div>
          )}

          {/* Evasion considerations */}
          {strategy.evasion_considerations && (
            <div className="bg-red-900/20 border border-red-800 rounded-lg p-4">
              <h5 className="text-sm font-medium text-red-300 mb-2 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Evasion Considerations
              </h5>
              <p className="text-sm text-gray-300">{strategy.evasion_considerations}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function TechniqueDetail() {
  const { techniqueId } = useParams<{ techniqueId: string }>()
  const navigate = useNavigate()
  const [cloudFilter, setCloudFilter] = useState<'all' | 'aws' | 'gcp'>('all')

  const { data: technique, isLoading, error } = useQuery({
    queryKey: ['technique', techniqueId],
    queryFn: () => api.get<TechniqueDetail>(`/techniques/${techniqueId}`).then(r => r.data),
    enabled: !!techniqueId,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
        <span className="ml-3 text-gray-400">Loading technique details...</span>
      </div>
    )
  }

  if (error || !technique) {
    return (
      <div className="bg-gray-800 rounded-lg p-8 text-center">
        <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">Template Not Available</h3>
        <p className="text-gray-400 mb-4">
          No remediation template is available for technique {techniqueId}.
        </p>
        <a
          href={`https://attack.mitre.org/techniques/${techniqueId?.replace('.', '/')}/`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300"
        >
          View on MITRE ATT&CK <ExternalLink className="w-4 h-4" />
        </a>
      </div>
    )
  }

  // Filter strategies by cloud provider
  const filteredStrategies =
    cloudFilter === 'all'
      ? technique.detection_strategies
      : technique.detection_strategies.filter(s => s.cloud_provider === cloudFilter)

  const awsCount = technique.detection_strategies.filter(s => s.cloud_provider === 'aws').length
  const gcpCount = technique.detection_strategies.filter(s => s.cloud_provider === 'gcp').length

  return (
    <div className="space-y-6">
      {/* Back button - uses browser history to return to previous page */}
      <button
        onClick={() => {
          // Use browser history if available, fallback to coverage page
          if (window.history.length > 1) {
            navigate(-1)
          } else {
            navigate('/coverage')
          }
        }}
        className="inline-flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back
      </button>

      {/* Header */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-2xl font-mono font-bold text-blue-400">
                {technique.technique_id}
              </span>
              <span
                className={`px-2 py-1 text-xs font-medium rounded ${
                  technique.threat_context.severity_score >= 8
                    ? 'bg-red-900/50 text-red-300'
                    : technique.threat_context.severity_score >= 5
                    ? 'bg-yellow-900/50 text-yellow-300'
                    : 'bg-green-900/50 text-green-300'
                }`}
              >
                Severity: {technique.threat_context.severity_score}/10
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white mb-2">{technique.technique_name}</h1>
            <div className="flex flex-wrap gap-2 mb-4">
              {technique.tactic_names.map((tactic, i) => (
                <span
                  key={technique.tactic_ids[i]}
                  className="px-2 py-1 text-xs font-medium bg-purple-900/50 text-purple-300 border border-purple-700 rounded"
                >
                  {tactic}
                </span>
              ))}
            </div>
            <p className="text-gray-300 max-w-3xl">{technique.threat_context.description}</p>
          </div>
          <a
            href={technique.mitre_url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300 transition-colors"
          >
            MITRE ATT&CK <ExternalLink className="w-4 h-4" />
          </a>
        </div>

        {/* Quick stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-6 pt-6 border-t border-gray-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-900/50 rounded-lg">
              <Shield className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <div className="text-xs text-gray-400">AWS Strategies</div>
              <div className="font-bold text-white">{awsCount}</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-900/50 rounded-lg">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <div className="text-xs text-gray-400">GCP Strategies</div>
              <div className="font-bold text-white">{gcpCount}</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-900/50 rounded-lg">
              <Clock className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <div className="text-xs text-gray-400">Total Effort</div>
              <div className="font-bold text-white">{technique.total_effort_hours}h</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-900/50 rounded-lg">
              <TrendingUp className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <div className="text-xs text-gray-400">Coverage Impact</div>
              <div className="font-bold text-white text-sm">{technique.coverage_improvement}</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-900/50 rounded-lg">
              <Target className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <div className="text-xs text-gray-400">Trend</div>
              <div className="font-bold text-white capitalize">{technique.threat_context.trend}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Intelligence */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <Zap className="w-5 h-5 text-yellow-400" />
          Threat Intelligence
        </h2>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Why attackers use this */}
          <div>
            <h3 className="text-sm font-medium text-gray-300 mb-2">Why Attackers Use This Technique</h3>
            <ul className="list-disc list-inside text-sm text-gray-400 space-y-1">
              {technique.threat_context.why_technique.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
          </div>

          {/* Business impact */}
          <div>
            <h3 className="text-sm font-medium text-gray-300 mb-2">Business Impact</h3>
            <ul className="list-disc list-inside text-sm text-gray-400 space-y-1">
              {technique.threat_context.business_impact.map((impact, i) => (
                <li key={i}>{impact}</li>
              ))}
            </ul>
          </div>
        </div>

        {/* Known threat actors */}
        {technique.threat_context.known_threat_actors.length > 0 && (
          <div className="mt-6 pt-6 border-t border-gray-700">
            <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
              <Users className="w-4 h-4" />
              Known Threat Actors
            </h3>
            <div className="flex flex-wrap gap-2">
              {technique.threat_context.known_threat_actors.map((actor) => (
                <span
                  key={actor}
                  className="px-2 py-1 text-xs font-medium bg-red-900/30 text-red-300 border border-red-800 rounded"
                >
                  {actor}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Recent campaigns */}
        {technique.threat_context.recent_campaigns.length > 0 && (
          <div className="mt-6 pt-6 border-t border-gray-700">
            <h3 className="text-sm font-medium text-gray-300 mb-3">Recent Campaigns</h3>
            <div className="space-y-3">
              {technique.threat_context.recent_campaigns.map((campaign) => (
                <div
                  key={campaign.name}
                  className="bg-gray-700/30 rounded-lg p-3"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-white">{campaign.name}</span>
                    <span className="text-xs text-gray-400">{campaign.year}</span>
                  </div>
                  <p className="text-sm text-gray-400">{campaign.description}</p>
                  {campaign.reference_url && (
                    <a
                      href={campaign.reference_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-400 hover:text-blue-300 mt-1 inline-flex items-center gap-1"
                    >
                      Reference <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Detection Strategies */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
            <FileCode className="w-5 h-5 text-green-600" />
            Detection Strategies
            <span className="text-sm font-normal text-gray-500">
              ({filteredStrategies.length} of {technique.detection_strategies.length})
            </span>
          </h2>

          {/* Cloud filter */}
          <div className="flex gap-2">
            <button
              onClick={() => setCloudFilter('all')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                cloudFilter === 'all'
                  ? 'bg-gray-700 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              All ({technique.detection_strategies.length})
            </button>
            <button
              onClick={() => setCloudFilter('aws')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                cloudFilter === 'aws'
                  ? 'bg-orange-600 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              AWS ({awsCount})
            </button>
            <button
              onClick={() => setCloudFilter('gcp')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                cloudFilter === 'gcp'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              GCP ({gcpCount})
            </button>
          </div>
        </div>

        <div className="space-y-4">
          {filteredStrategies.map((strategy, index) => (
            <StrategyCard
              key={strategy.strategy_id}
              strategy={strategy}
              defaultOpen={index === 0}
            />
          ))}
        </div>

        {filteredStrategies.length === 0 && (
          <div className="bg-white border border-gray-200 rounded-lg p-8 text-center shadow-sm">
            <p className="text-gray-600">
              No {cloudFilter.toUpperCase()} strategies available for this technique.
            </p>
            <button
              onClick={() => setCloudFilter('all')}
              className="mt-2 text-blue-600 hover:text-blue-700"
            >
              Show all strategies
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
