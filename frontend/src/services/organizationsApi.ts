/**
 * Cloud Organisations API
 *
 * API functions for managing AWS Organisations and GCP Organisations.
 */

import api from './api'

// Types for Cloud Organisations
export interface CloudOrganization {
  id: string
  organization_id: string
  provider: 'aws' | 'gcp'
  cloud_org_id: string
  name: string
  status: 'discovering' | 'active' | 'partial' | 'error' | 'disconnected'
  total_accounts_discovered: number
  total_accounts_connected: number
  hierarchy_data: {
    folders?: Array<{
      folder_id: string
      display_name: string
      parent_type: string
      parent_id: string
    }>
    org_units?: Array<{
      ou_id: string
      name: string
      parent_id: string
    }>
    org_policies?: Record<string, unknown>
  } | null
  credentials_arn: string | null
  last_sync_at: string | null
  created_at: string
  updated_at: string
}

export interface CloudOrganizationMember {
  id: string
  cloud_organization_id: string
  member_account_id: string
  member_name: string
  hierarchy_path: string
  status: 'discovered' | 'connecting' | 'connected' | 'skipped' | 'error' | 'suspended'
  cloud_account_id: string | null
  metadata: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface DiscoverOrganizationRequest {
  provider: 'aws' | 'gcp'
  credentials_arn?: string
  gcp_org_id?: string
  gcp_service_account_email?: string
  gcp_project_id?: string
}

export interface DiscoverOrganizationResponse {
  organization_id: string
  message: string
  total_accounts_discovered: number
  scan_id?: string
}

export interface ConnectMembersRequest {
  member_ids: string[]
}

export interface ConnectMembersResponse {
  message: string
  connected_count: number
  skipped_count: number
  results: Array<{
    member_id: string
    status: 'connected' | 'skipped' | 'error'
    cloud_account_id?: string
    error?: string
  }>
}

// Organisation Coverage Types
export interface OrgTacticCoverage {
  tactic_id: string
  tactic_name: string
  total_techniques: number
  union_covered: number
  minimum_covered: number
  union_percent: number
  minimum_percent: number
}

export interface AccountCoverageSummary {
  cloud_account_id: string
  account_name: string
  account_id: string
  coverage_percent: number
  covered_techniques: number
  total_techniques: number
}

export interface OrgCoverageData {
  id: string
  cloud_organization_id: string
  total_member_accounts: number
  connected_accounts: number
  total_techniques: number
  union_covered_techniques: number
  minimum_covered_techniques: number
  average_coverage_percent: number
  union_coverage_percent: number
  minimum_coverage_percent: number
  org_detection_count: number
  org_covered_techniques: number
  tactic_coverage: OrgTacticCoverage[]
  per_account_coverage: AccountCoverageSummary[] | null
  mitre_version: string
  created_at: string
}

// API Functions
export const cloudOrganizationsApi = {
  // List all connected cloud organisations
  list: () =>
    api.get<CloudOrganization[]>('/cloud-organizations').then((r) => r.data),

  // Get a specific cloud organisation
  get: (id: string) =>
    api.get<CloudOrganization>(`/cloud-organizations/${id}`).then((r) => r.data),

  // Discover a new organisation
  discover: (data: DiscoverOrganizationRequest) =>
    api
      .post<DiscoverOrganizationResponse>('/cloud-organizations/discover', data)
      .then((r) => r.data),

  // Get members of an organisation
  getMembers: (orgId: string) =>
    api
      .get<CloudOrganizationMember[]>(`/cloud-organizations/${orgId}/members`)
      .then((r) => r.data),

  // Connect selected members
  connectMembers: (orgId: string, data: ConnectMembersRequest) =>
    api
      .post<ConnectMembersResponse>(
        `/cloud-organizations/${orgId}/connect-members`,
        data
      )
      .then((r) => r.data),

  // Sync organisation (rediscover members)
  sync: (orgId: string) =>
    api.post(`/cloud-organizations/${orgId}/sync`).then((r) => r.data),

  // Delete organisation
  delete: (orgId: string) =>
    api.delete(`/cloud-organizations/${orgId}`).then((r) => r.data),
}

// Organisation Coverage API
export const orgCoverageApi = {
  // Get aggregate coverage for an organisation
  get: (orgId: string) =>
    api
      .get<OrgCoverageData>(`/coverage/organization/${orgId}`)
      .then((r) => r.data),

  // Calculate/refresh organisation coverage
  calculate: (orgId: string) =>
    api
      .post<OrgCoverageData>(`/coverage/organization/${orgId}/calculate`)
      .then((r) => r.data),
}

export default cloudOrganizationsApi
