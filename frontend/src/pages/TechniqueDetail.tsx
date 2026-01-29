/**
 * Technique Detail Page.
 *
 * Displays remediation templates and detection strategies for a MITRE ATT&CK technique.
 * Shows cloud-specific implementation guidance (AWS/GCP/Azure) with IaC templates.
 */

import { useState, useEffect, useMemo } from 'react'
import { useParams } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { useSelectedAccount } from '../hooks/useSelectedAccount'
import {
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
import { PageHeader } from '../components/navigation'

// API types
interface AttributedGroup {
  external_id: string
  name: string
  mitre_url: string
}

interface Campaign {
  name: string
  year: number
  description: string
  reference_url?: string
  attributed_groups?: AttributedGroup[]
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
  // Azure fields
  azure_kql_query?: string
  sentinel_rule_query?: string
  azure_terraform_template?: string
  arm_template?: string
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
  azure_service?: string
  cloud_provider: string
  implementation: DetectionImplementation
  estimated_false_positive_rate: string
  false_positive_tuning?: string
  detection_coverage?: string
  evasion_considerations?: string
  implementation_effort: string
  implementation_time?: string
  estimated_monthly_cost?: string  // Legacy field
  prerequisites: string[]
  // New cost fields
  cost_tier?: string  // "low", "medium", "high"
  pricing_basis?: string  // e.g., "$0.005 per GB scanned"
  pricing_url?: string  // Link to official pricing page
}

interface EffortEstimates {
  quick_win_hours: number
  typical_hours: number
  comprehensive_hours: number
  strategy_count: number
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
  effort_estimates: EffortEstimates
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
          className="p-1.5 rounded-sm bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
          title="Copy to clipboard"
        >
          {copied ? (
            <Check className="w-4 h-4 text-green-400" />
          ) : (
            <Copy className="w-4 h-4" />
          )}
        </button>
      </div>
      <div className="text-xs text-gray-400 mb-1">{language}</div>
      <pre className="bg-gray-900 rounded-lg p-4 overflow-x-auto text-sm text-gray-300 font-mono">
        <code>{code}</code>
      </pre>
    </div>
  )
}

// Detection strategy card component
function StrategyCard({ strategy, defaultOpen }: { strategy: DetectionStrategy; defaultOpen: boolean }) {
  const [isOpen, setIsOpen] = useState(defaultOpen)
  const [activeTab, setActiveTab] = useState<'cloudformation' | 'terraform' | 'gcp' | 'azure' | 'arm'>('terraform')
  const [templatesExpanded, setTemplatesExpanded] = useState(false)

  // Provider badge styles (AWS=orange, GCP=blue, Azure=cyan)
  const providerStyles: Record<string, { bg: string; label: string }> = {
    aws: { bg: 'bg-orange-900/50 text-orange-300 border-orange-700', label: 'AWS' },
    gcp: { bg: 'bg-blue-900/50 text-blue-300 border-blue-700', label: 'GCP' },
    azure: { bg: 'bg-cyan-900/50 text-cyan-300 border-cyan-700', label: 'Azure' },
  }
  const providerStyle = providerStyles[strategy.cloud_provider] || providerStyles.aws

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
            className={`px-2 py-1 text-xs font-medium rounded border ${providerStyle.bg}`}
          >
            {providerStyle.label}
          </span>
          <div className="text-left">
            <h4 className="font-medium text-white">{strategy.name}</h4>
            <p className="text-sm text-gray-400">{strategy.detection_type.replace(/_/g, ' ')}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`px-2 py-0.5 text-xs font-medium rounded-sm border ${getEffortBadge(strategy.implementation_effort)}`}>
            {strategy.implementation_effort} effort
          </span>
          <span className={`px-2 py-0.5 text-xs font-medium rounded-sm border ${getFPRBadge(strategy.estimated_false_positive_rate)}`}>
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
            {/* Cost Information */}
            {(strategy.cost_tier || strategy.pricing_basis) && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">Cost</div>
                <div className="space-y-1">
                  {strategy.cost_tier && (
                    <span className={`inline-block px-2 py-0.5 text-xs font-medium rounded ${
                      strategy.cost_tier === 'low'
                        ? 'bg-green-900/50 text-green-300'
                        : strategy.cost_tier === 'medium'
                        ? 'bg-yellow-900/50 text-yellow-300'
                        : 'bg-red-900/50 text-red-300'
                    }`}>
                      {strategy.cost_tier.charAt(0).toUpperCase() + strategy.cost_tier.slice(1)}
                    </span>
                  )}
                  {strategy.pricing_basis && (
                    <div className="text-xs text-gray-300">{strategy.pricing_basis}</div>
                  )}
                  {strategy.pricing_url && (
                    <a
                      href={strategy.pricing_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                    >
                      Pricing <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              </div>
            )}
            {strategy.detection_coverage && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">Coverage</div>
                <div className="font-medium text-white text-sm">{strategy.detection_coverage}</div>
              </div>
            )}
            {strategy.aws_service && strategy.aws_service !== 'n/a' && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">AWS Service</div>
                <div className="font-medium text-orange-400">{strategy.aws_service}</div>
              </div>
            )}
            {strategy.gcp_service && strategy.gcp_service !== 'n/a' && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">GCP Service</div>
                <div className="font-medium text-blue-400">{strategy.gcp_service}</div>
              </div>
            )}
            {strategy.azure_service && strategy.azure_service !== 'n/a' && (
              <div className="bg-gray-700/30 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">Azure Service</div>
                <div className="font-medium text-cyan-400">{strategy.azure_service}</div>
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
                <span className="text-xs text-gray-400">
                  ({[
                    strategy.implementation.terraform_template && 'Terraform',
                    strategy.implementation.cloudformation_template && 'CloudFormation',
                    strategy.implementation.gcp_terraform_template && 'GCP Terraform',
                    strategy.implementation.azure_terraform_template && 'Azure Terraform',
                    strategy.implementation.arm_template && 'ARM',
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
                  {strategy.implementation.azure_terraform_template && (
                    <button
                      onClick={() => setActiveTab('azure')}
                      className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                        activeTab === 'azure'
                          ? 'bg-cyan-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      Terraform (Azure)
                    </button>
                  )}
                  {strategy.implementation.arm_template && (
                    <button
                      onClick={() => setActiveTab('arm')}
                      className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                        activeTab === 'arm'
                          ? 'bg-cyan-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      ARM Template
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
                {activeTab === 'azure' && strategy.implementation.azure_terraform_template && (
                  <CodeBlock code={strategy.implementation.azure_terraform_template} language="Terraform (Azure)" />
                )}
                {activeTab === 'arm' && strategy.implementation.arm_template && (
                  <CodeBlock code={strategy.implementation.arm_template} language="ARM Template (JSON)" />
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

          {strategy.implementation.azure_kql_query && (
            <div>
              <h5 className="text-sm font-medium text-gray-300 mb-2 flex items-center gap-2">
                <Search className="w-4 h-4" />
                Azure Log Analytics / Sentinel Query (KQL)
              </h5>
              <CodeBlock code={strategy.implementation.azure_kql_query} language="Kusto (KQL)" />
            </div>
          )}

          {strategy.implementation.sentinel_rule_query && strategy.implementation.sentinel_rule_query !== strategy.implementation.azure_kql_query && (
            <div>
              <h5 className="text-sm font-medium text-gray-300 mb-2 flex items-center gap-2">
                <Search className="w-4 h-4" />
                Microsoft Sentinel Analytics Rule
              </h5>
              <CodeBlock code={strategy.implementation.sentinel_rule_query} language="Kusto (KQL)" />
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

// Helper to parse implementation time strings like "30 minutes", "1-2 hours"
function parseImplementationTime(timeStr: string | undefined): number {
  if (!timeStr) return 0
  const str = timeStr.toLowerCase().trim()

  // Handle "30 minutes - 1 hour" format
  if (str.includes(' - ')) {
    const parts = str.split(' - ')
    if (parts.length === 2) {
      const lower = parseImplementationTime(parts[0])
      const upper = parseImplementationTime(parts[1])
      return (lower + upper) / 2
    }
  }

  // Handle "1-2 hours" format
  const rangeMatch = str.match(/(\d+(?:\.\d+)?)\s*-\s*(\d+(?:\.\d+)?)\s*hour/)
  if (rangeMatch) {
    const lower = parseFloat(rangeMatch[1])
    const upper = parseFloat(rangeMatch[2])
    return (lower + upper) / 2
  }

  // Handle "X minutes"
  const minuteMatch = str.match(/(\d+(?:\.\d+)?)\s*minute/)
  if (minuteMatch) {
    return parseFloat(minuteMatch[1]) / 60
  }

  // Handle "X hours"
  const hourMatch = str.match(/(\d+(?:\.\d+)?)\s*hour/)
  if (hourMatch) {
    return parseFloat(hourMatch[1])
  }

  return 0
}

export default function TechniqueDetail() {
  const { techniqueId } = useParams<{ techniqueId: string }>()
  const { selectedAccount } = useSelectedAccount()

  // Initialize filter based on selected account's cloud provider
  const [cloudFilter, setCloudFilter] = useState<'all' | 'aws' | 'gcp' | 'azure'>(() => {
    if (selectedAccount?.provider === 'gcp') return 'gcp'
    if (selectedAccount?.provider === 'aws') return 'aws'
    if (selectedAccount?.provider === 'azure') return 'azure'
    return 'all'
  })

  const { data: technique, isLoading, error } = useQuery({
    queryKey: ['technique', techniqueId],
    queryFn: () => api.get<TechniqueDetail>(`/techniques/${techniqueId}`).then(r => r.data),
    enabled: !!techniqueId,
  })

  // Sync filter when account changes (must be before early returns)
  useEffect(() => {
    if (selectedAccount?.provider) {
      setCloudFilter(selectedAccount.provider)
    }
  }, [selectedAccount?.provider])

  // Calculate effort estimates based on current filter (must be before early returns)
  const filteredEffortEstimates = useMemo(() => {
    if (!technique) {
      return { quick_win_hours: 0, typical_hours: 0, comprehensive_hours: 0, strategy_count: 0 }
    }

    const strategies = cloudFilter === 'all'
      ? technique.detection_strategies
      : technique.detection_strategies.filter(s => s.cloud_provider === cloudFilter)

    if (strategies.length === 0) {
      return { quick_win_hours: 0, typical_hours: 0, comprehensive_hours: 0, strategy_count: 0 }
    }

    // Build strategy map for ordering
    const strategyMap = Object.fromEntries(strategies.map(s => [s.strategy_id, s]))

    // Get ordered strategies based on recommended_order
    const orderedStrategies: DetectionStrategy[] = []
    for (const id of technique.recommended_order) {
      if (strategyMap[id]) {
        orderedStrategies.push(strategyMap[id])
      }
    }
    // Add any strategies not in recommended_order
    for (const s of strategies) {
      if (!orderedStrategies.includes(s)) {
        orderedStrategies.push(s)
      }
    }

    // Parse hours for each strategy
    const hours = orderedStrategies.map(s => parseImplementationTime(s.implementation_time))

    return {
      // Quick win = first strategy only (single fastest action)
      quick_win_hours: parseFloat((hours[0] || 0).toFixed(1)),
      typical_hours: parseFloat(hours.slice(0, 3).reduce((a, b) => a + b, 0).toFixed(1)),
      comprehensive_hours: parseFloat(hours.reduce((a, b) => a + b, 0).toFixed(1)),
      strategy_count: strategies.length,
    }
  }, [technique, cloudFilter])

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
  const azureCount = technique.detection_strategies.filter(s => s.cloud_provider === 'azure').length

  return (
    <div className="space-y-6">
      <PageHeader back={{ label: "Coverage", fallback: "/coverage" }} />

      {/* Header Card */}
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
                  className="px-2 py-1 text-xs font-medium bg-purple-900/50 text-purple-300 border border-purple-700 rounded-sm"
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
              <div className="text-xs text-gray-400">Quick Win</div>
              <div className="font-bold text-white">{filteredEffortEstimates.quick_win_hours}h</div>
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

        {/* Tiered Effort Estimates */}
        <div className="mt-6 pt-6 border-t border-gray-700">
          <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
            <Clock className="w-4 h-4 text-gray-400" />
            Implementation Effort Estimates
            {cloudFilter !== 'all' && (
              <span className={`text-xs px-2 py-0.5 rounded ${
                cloudFilter === 'aws' ? 'bg-orange-900/50 text-orange-300' : 'bg-blue-900/50 text-blue-300'
              }`}>
                {cloudFilter.toUpperCase()} only
              </span>
            )}
          </h3>
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-green-900/30 rounded-lg p-3 border border-green-700/50">
              <div className="text-green-400 text-xs font-medium">Quick Win</div>
              <div className="text-xl font-bold text-white mt-1">
                {filteredEffortEstimates.quick_win_hours}h
              </div>
              <div className="text-gray-500 text-xs mt-1">Top strategy</div>
            </div>
            <div className="bg-yellow-900/30 rounded-lg p-3 border border-yellow-700/50">
              <div className="text-yellow-400 text-xs font-medium">Typical</div>
              <div className="text-xl font-bold text-white mt-1">
                {filteredEffortEstimates.typical_hours}h
              </div>
              <div className="text-gray-500 text-xs mt-1">
                {filteredEffortEstimates.strategy_count <= 3
                  ? `All ${filteredEffortEstimates.strategy_count} strategies`
                  : 'First 3 strategies'}
              </div>
            </div>
            <div className="bg-blue-900/30 rounded-lg p-3 border border-blue-700/50">
              <div className="text-blue-400 text-xs font-medium">Comprehensive</div>
              <div className="text-xl font-bold text-white mt-1">
                {filteredEffortEstimates.comprehensive_hours}h
              </div>
              <div className="text-gray-500 text-xs mt-1">
                {cloudFilter === 'all'
                  ? `All ${filteredEffortEstimates.strategy_count} strategies`
                  : `All ${filteredEffortEstimates.strategy_count} ${cloudFilter.toUpperCase()} strategies`}
              </div>
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
                  className="px-2 py-1 text-xs font-medium bg-red-900/30 text-red-300 border border-red-800 rounded-sm"
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
                  {campaign.attributed_groups && campaign.attributed_groups.length > 0 && (
                    <div className="flex items-center gap-2 mt-2">
                      <span className="text-xs text-gray-400">Attributed to:</span>
                      <div className="flex flex-wrap gap-1">
                        {campaign.attributed_groups.map((group) => (
                          <a
                            key={group.external_id}
                            href={group.mitre_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-900/30 text-red-400 text-xs rounded-full hover:bg-red-900/50"
                          >
                            {group.name}
                            <span className="text-red-500/70">({group.external_id})</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
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
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <FileCode className="w-5 h-5 text-green-400" />
            Detection Strategies
            <span className="text-sm font-normal text-gray-400">
              ({filteredStrategies.length} of {technique.detection_strategies.length})
            </span>
          </h2>

          {/* Cloud filter */}
          <div className="flex gap-2">
            <button
              onClick={() => setCloudFilter('all')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                cloudFilter === 'all'
                  ? 'bg-gray-600 text-white'
                  : 'bg-gray-700/50 text-gray-300 hover:bg-gray-700'
              }`}
            >
              All ({technique.detection_strategies.length})
            </button>
            <button
              onClick={() => setCloudFilter('aws')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                cloudFilter === 'aws'
                  ? 'bg-orange-600 text-white'
                  : 'bg-gray-700/50 text-gray-300 hover:bg-gray-700'
              }`}
            >
              AWS ({awsCount})
            </button>
            <button
              onClick={() => setCloudFilter('gcp')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                cloudFilter === 'gcp'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700/50 text-gray-300 hover:bg-gray-700'
              }`}
            >
              GCP ({gcpCount})
            </button>
            <button
              onClick={() => setCloudFilter('azure')}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                cloudFilter === 'azure'
                  ? 'bg-cyan-600 text-white'
                  : 'bg-gray-700/50 text-gray-300 hover:bg-gray-700'
              }`}
            >
              Azure ({azureCount})
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
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
            <p className="text-gray-400">
              No {cloudFilter.toUpperCase()} strategies available for this technique.
            </p>
            <button
              onClick={() => setCloudFilter('all')}
              className="mt-2 text-blue-400 hover:text-blue-300"
            >
              Show all strategies
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
