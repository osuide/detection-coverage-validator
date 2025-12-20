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

export interface ControlResponse {
  id: string
  control_id: string
  control_family: string
  name: string
  description: string | null
  priority: string | null
  is_enhancement: boolean
  mapped_technique_count: number
}

export interface TechniqueMapping {
  technique_id: string
  technique_name: string
  mapping_type: string
  mapping_source: string
}

export interface ComplianceCoverageSummary {
  framework_id: string
  framework_name: string
  coverage_percent: number
  covered_controls: number
  total_controls: number
}

export interface FamilyCoverageItem {
  family: string
  total: number
  covered: number
  partial: number
  uncovered: number
  percent: number
}

export interface ControlGapItem {
  control_id: string
  control_name: string
  control_family: string
  priority: string | null
  coverage_percent: number
  missing_techniques: string[]
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
