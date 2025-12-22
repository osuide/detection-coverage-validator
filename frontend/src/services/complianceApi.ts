/**
 * Compliance Framework API service.
 *
 * Provides methods to fetch compliance framework coverage data.
 */

import api from './api'

export interface ComplianceFramework {
  id: string
  framework_id: string
  name: string
  version: string
  description: string | null
  source_url: string | null
  total_controls: number
  is_active: boolean
}

export interface CloudContext {
  aws_services: string[]
  gcp_services: string[]
  shared_responsibility: 'customer' | 'shared' | 'provider'
  detection_guidance: string | null
}

export type CloudApplicability =
  | 'highly_relevant'
  | 'moderately_relevant'
  | 'informational'
  | 'provider_responsibility'

export interface ControlResponse {
  id: string
  control_id: string
  control_family: string
  name: string
  description: string | null
  priority: string | null
  is_enhancement: boolean
  mapped_technique_count: number
  cloud_applicability: CloudApplicability | null
  cloud_context: CloudContext | null
}

export interface TechniqueMapping {
  technique_id: string
  technique_name: string
  mapping_type: string
  mapping_source: string
}

export interface CloudCoverageMetrics {
  cloud_detectable_total: number
  cloud_detectable_covered: number
  cloud_coverage_percent: number
  customer_responsibility_total: number
  customer_responsibility_covered: number
  provider_managed_total: number
  not_assessable_total: number // Controls that cannot be assessed via cloud scanning
}

export interface ComplianceCoverageSummary {
  framework_id: string
  framework_name: string
  coverage_percent: number
  covered_controls: number
  total_controls: number
  cloud_coverage_percent: number | null
}

export interface FamilyCoverageItem {
  family: string
  total: number
  covered: number
  partial: number
  uncovered: number
  not_assessable: number // Controls that cannot be assessed via cloud scanning
  percent: number
  cloud_applicability?: CloudApplicability
  shared_responsibility?: 'customer' | 'shared' | 'provider'
}

export interface ControlGapItem {
  control_id: string
  control_name: string
  control_family: string
  priority: string | null
  coverage_percent: number
  missing_techniques: string[]
  cloud_applicability?: CloudApplicability
  cloud_context?: CloudContext
}

export interface ComplianceCoverage {
  id: string
  cloud_account_id: string
  framework: ComplianceFramework
  total_controls: number
  covered_controls: number
  partial_controls: number
  uncovered_controls: number
  coverage_percent: number
  cloud_metrics: CloudCoverageMetrics | null
  family_coverage: FamilyCoverageItem[]
  top_gaps: ControlGapItem[]
  created_at: string
}

export const complianceApi = {
  /**
   * Get all active compliance frameworks.
   */
  getFrameworks: () =>
    api.get<ComplianceFramework[]>('/compliance/frameworks').then((r) => r.data),

  /**
   * Get a specific compliance framework.
   */
  getFramework: (frameworkId: string) =>
    api
      .get<ComplianceFramework>(`/compliance/frameworks/${frameworkId}`)
      .then((r) => r.data),

  /**
   * Get all controls for a framework.
   */
  getControls: (frameworkId: string) =>
    api
      .get<ControlResponse[]>(`/compliance/frameworks/${frameworkId}/controls`)
      .then((r) => r.data),

  /**
   * Get MITRE techniques mapped to a control.
   */
  getControlTechniques: (controlId: string) =>
    api
      .get<TechniqueMapping[]>(`/compliance/controls/${controlId}/techniques`)
      .then((r) => r.data),

  /**
   * Get compliance coverage summary for all frameworks.
   */
  getSummary: (accountId: string) =>
    api
      .get<ComplianceCoverageSummary[]>(`/compliance/coverage/${accountId}`)
      .then((r) => r.data),

  /**
   * Get detailed compliance coverage for a specific framework.
   */
  getCoverage: (accountId: string, frameworkId: string) =>
    api
      .get<ComplianceCoverage>(`/compliance/coverage/${accountId}/${frameworkId}`)
      .then((r) => r.data),
}
