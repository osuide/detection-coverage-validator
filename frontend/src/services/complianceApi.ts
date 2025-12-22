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

export interface MissingTechniqueDetail {
  technique_id: string
  technique_name: string
  has_template: boolean
  tactic_ids: string[]
}

export interface ControlGapItem {
  control_id: string
  control_name: string
  control_family: string
  priority: string | null
  coverage_percent: number
  missing_techniques: string[]
  missing_technique_details: MissingTechniqueDetail[]
  cloud_applicability?: CloudApplicability
  cloud_context?: CloudContext
}

export interface ControlStatusItem {
  control_id: string
  control_name: string
  control_family: string
  priority: string | null
  coverage_percent: number
  mapped_techniques: number
  covered_techniques: number
  cloud_applicability?: CloudApplicability
  shared_responsibility?: 'customer' | 'shared' | 'provider'
}

export interface ControlsByStatus {
  covered: ControlStatusItem[]
  partial: ControlStatusItem[]
  uncovered: ControlStatusItem[]
  not_assessable: ControlStatusItem[]
}

export interface ControlsByCloudCategory {
  cloud_detectable: ControlStatusItem[]
  customer_responsibility: ControlStatusItem[]
  provider_managed: ControlStatusItem[]
  not_assessable: ControlStatusItem[]
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
  controls_by_status?: ControlsByStatus
  controls_by_cloud_category?: ControlsByCloudCategory
  created_at: string
}

// Control Coverage Detail types
export interface DetectionSummary {
  id: string
  name: string
  source: string
  confidence: number
}

export interface TechniqueCoverageDetail {
  technique_id: string
  technique_name: string
  status: 'covered' | 'partial' | 'uncovered'
  confidence: number | null
  detections: DetectionSummary[]
  has_template: boolean
}

export interface ControlCoverageDetail {
  control_id: string
  control_name: string
  control_family: string
  description: string | null
  priority: string | null
  status: 'covered' | 'partial' | 'uncovered' | 'not_assessable'
  coverage_percent: number
  coverage_rationale: string
  mapped_techniques: number
  covered_techniques: number
  cloud_applicability: CloudApplicability | null
  cloud_context: CloudContext | null
  techniques: TechniqueCoverageDetail[]
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

  /**
   * Get detailed coverage breakdown for a single control.
   * Shows which techniques are covered vs. uncovered and what detections provide coverage.
   */
  getControlCoverageDetail: (
    controlId: string,
    accountId: string,
    frameworkId: string
  ) =>
    api
      .get<ControlCoverageDetail>(
        `/compliance/controls/${controlId}/coverage`,
        {
          params: {
            cloud_account_id: accountId,
            framework_id: frameworkId,
          },
        }
      )
      .then((r) => r.data),
}
