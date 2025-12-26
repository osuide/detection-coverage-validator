import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { useAuthStore, authActions } from '../stores/authStore'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  withCredentials: true, // Send cookies for httpOnly refresh token
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add auth token interceptor - read from Zustand store (memory), not localStorage
api.interceptors.request.use((config) => {
  const { accessToken } = useAuthStore.getState()
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  return config
})

// Flag to prevent multiple refresh attempts
let isRefreshing = false
let failedQueue: Array<{
  resolve: (token: string) => void
  reject: (error: unknown) => void
}> = []

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error)
    } else {
      prom.resolve(token!)
    }
  })
  failedQueue = []
}

// Response interceptor to handle 401 and auto-refresh token
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    // If 401 and not already retrying
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // Wait for the refresh to complete
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        })
          .then((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`
            return api(originalRequest)
          })
          .catch((err) => Promise.reject(err))
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        // Use authActions to refresh via httpOnly cookie
        const newAccessToken = await authActions.refreshToken()

        if (!newAccessToken) {
          // No valid session - process queue BEFORE redirecting to prevent orphaned promises
          const sessionExpiredError = new Error('Session expired')
          processQueue(sessionExpiredError, null)
          useAuthStore.getState().clearAuth()
          window.location.href = '/login'
          return Promise.reject(error)
        }

        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`
        processQueue(null, newAccessToken)

        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        // Refresh failed, clear auth and redirect to login
        useAuthStore.getState().clearAuth()
        window.location.href = '/login'
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  }
)

// Types
export type RegionScanMode = 'all' | 'selected' | 'auto'

export interface RegionConfig {
  mode: RegionScanMode
  regions?: string[]
  excluded_regions?: string[]
  discovered_regions?: string[]
  auto_discovered_at?: string
}

export interface CloudAccount {
  id: string
  name: string
  provider: 'aws' | 'gcp'
  account_id: string
  regions: string[]
  region_config?: RegionConfig
  is_active: boolean
  last_scan_at: string | null
  created_at: string
}

export interface AvailableRegionsResponse {
  provider: 'aws' | 'gcp'
  regions: string[]
  default_regions: string[]
}

export interface DiscoverRegionsResponse {
  discovered_regions: string[]
  discovery_method: string
  discovered_at: string
}

export interface Detection {
  id: string
  cloud_account_id: string
  name: string
  detection_type: string
  status: string
  region: string
  mapping_count: number
  discovered_at: string
}

export interface TacticCoverage {
  tactic_id: string
  tactic_name: string
  covered: number
  partial: number
  uncovered: number
  total: number
  percent: number
}

export interface RecommendedStrategy {
  strategy_id: string
  name: string
  detection_type: string
  aws_service: string
  implementation_effort: string
  estimated_time: string
  detection_coverage: string
  has_query: boolean
  has_cloudformation: boolean
  has_terraform: boolean
  // GCP support
  gcp_service?: string
  cloud_provider?: string
  has_gcp_query?: boolean
  has_gcp_terraform?: boolean
}

export interface Gap {
  technique_id: string
  technique_name: string
  tactic_id: string
  tactic_name: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  reason: string
  data_sources: string[]
  recommended_detections: string[]
  // Enhanced remediation data
  has_template: boolean
  severity_score: number | null
  threat_actors: string[]
  business_impact: string[]
  quick_win_strategy: string | null
  total_effort_hours: number | null
  mitre_url: string | null
  recommended_strategies: RecommendedStrategy[]
}

export interface SecurityFunctionBreakdown {
  detect: number
  protect: number
  identify: number
  recover: number
  operational: number
  total: number
}

export interface CoverageData {
  id: string
  cloud_account_id: string
  total_techniques: number
  covered_techniques: number
  partial_techniques: number
  uncovered_techniques: number
  coverage_percent: number
  average_confidence: number
  tactic_coverage: TacticCoverage[]
  total_detections: number
  active_detections: number
  mapped_detections: number
  top_gaps: Gap[]
  mitre_version: string
  created_at: string
  security_function_breakdown?: SecurityFunctionBreakdown
}

export interface Scan {
  id: string
  cloud_account_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress_percent: number
  current_step: string | null
  detections_found: number
  created_at: string
}

export interface TechniqueCoverage {
  technique_id: string
  technique_name: string
  tactic_id: string
  tactic_name: string
  detection_count: number
  max_confidence: number
  status: 'covered' | 'partial' | 'uncovered'
  detection_names: string[]
  has_template: boolean
}

// API functions
export const accountsApi = {
  list: () => api.get<CloudAccount[]>('/accounts').then(r => r.data),
  get: (id: string) => api.get<CloudAccount>(`/accounts/${id}`).then(r => r.data),
  create: (data: Partial<CloudAccount>) => api.post<CloudAccount>('/accounts', data).then(r => r.data),
  update: (id: string, data: Partial<CloudAccount>) => api.patch<CloudAccount>(`/accounts/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/accounts/${id}`),
}

export const regionsApi = {
  getAvailable: (provider: 'aws' | 'gcp') =>
    api.get<AvailableRegionsResponse>(`/accounts/regions/${provider}`).then(r => r.data),
  discover: (accountId: string) =>
    api.post<DiscoverRegionsResponse>(`/accounts/${accountId}/discover-regions`).then(r => r.data),
}

export const scansApi = {
  list: (accountId?: string) =>
    api.get<{ items: Scan[] }>('/scans', { params: { cloud_account_id: accountId } }).then(r => r.data.items),
  create: (data: { cloud_account_id: string; regions?: string[] }) =>
    api.post<Scan>('/scans', data).then(r => r.data),
  get: (id: string) => api.get<Scan>(`/scans/${id}`).then(r => r.data),
}

export interface DetectionMapping {
  id: string
  technique_id: string
  technique_name: string
  confidence: number
  mapping_source: string
  rationale: string
  matched_indicators: string[] | null
  created_at: string | null
}

export interface DetectionDetail extends Detection {
  source_arn: string
  query_pattern: string | null
  event_pattern: object | null
  log_groups: string[] | null
  description: string | null
  health_score: number | null
  is_managed: boolean
}

export const detectionsApi = {
  list: (params?: { cloud_account_id?: string; page?: number; limit?: number }) =>
    api.get<{ items: Detection[]; total: number }>('/detections', { params }).then(r => r.data),
  get: (id: string) => api.get<DetectionDetail>(`/detections/${id}`).then(r => r.data),
  getMappings: (id: string) =>
    api.get<{ detection_id: string; detection_name: string; mappings: DetectionMapping[] }>(
      `/detections/${id}/mappings`
    ).then(r => r.data),
}

export const coverageApi = {
  get: (accountId: string) => api.get<CoverageData>(`/coverage/${accountId}`).then(r => r.data),
  calculate: (accountId: string) => api.post<CoverageData>(`/coverage/${accountId}/calculate`).then(r => r.data),
  getTechniques: (accountId: string) =>
    api.get<{ techniques: TechniqueCoverage[] }>(`/coverage/${accountId}/techniques`).then(r => r.data.techniques),
}

// Credential types
export interface SetupInstructions {
  provider: string
  external_id: string | null
  iam_policy: object | null
  custom_role: object | null
  required_permissions: Array<{
    action?: string
    permission?: string
    service: string
    purpose: string
  }>
  not_requested: string[]
  cloudformation_template_url: string | null
  terraform_module_url: string | null
  gcloud_commands: string[] | null
  manual_steps: string[]
}

export interface CloudCredential {
  id: string
  cloud_account_id: string
  credential_type: string
  status: 'pending' | 'valid' | 'invalid' | 'expired' | 'permission_error'
  status_message: string | null
  last_validated_at: string | null
  granted_permissions: string[] | null
  missing_permissions: string[] | null
  aws_role_arn: string | null
  aws_external_id: string | null
  gcp_project_id: string | null
  gcp_service_account_email: string | null
}

export interface ValidationResult {
  status: string
  message: string
  granted_permissions: string[]
  missing_permissions: string[]
}

// Strategy detail with full implementation artefacts
export interface StrategyDetail {
  strategy_id: string
  name: string
  description: string
  detection_type: string
  aws_service: string
  query: string | null
  event_pattern: Record<string, unknown> | null
  guardduty_finding_types: string[] | null
  cloudformation_template: string | null
  terraform_template: string | null
  alert_severity: string
  alert_title: string
  alert_description_template: string
  investigation_steps: string[]
  containment_actions: string[]
  estimated_false_positive_rate: string
  false_positive_tuning: string
  detection_coverage: string
  evasion_considerations: string
  implementation_effort: string
  implementation_time: string
  estimated_monthly_cost: string
  prerequisites: string[]
}

export const recommendationsApi = {
  getStrategyDetails: (techniqueId: string, strategyId: string) =>
    api.get<StrategyDetail>(`/recommendations/techniques/${techniqueId}/strategies/${strategyId}`).then(r => r.data),
}

// Scan status (for free tier limits)
export interface ScanStatus {
  can_scan: boolean
  scans_used: number
  scans_allowed: number
  unlimited: boolean
  next_available_at: string | null
  week_resets_at: string | null
}

export const scanStatusApi = {
  get: () => api.get<ScanStatus>('/billing/scan-status').then(r => r.data),
}

export const credentialsApi = {
  getSetupInstructions: (accountId: string) =>
    api.get<SetupInstructions>(`/credentials/setup/${accountId}`).then(r => r.data),

  getCredential: (accountId: string) =>
    api.get<CloudCredential>(`/credentials/${accountId}`).then(r => r.data),

  createAWSCredential: (data: { cloud_account_id: string; role_arn: string }) =>
    api.post<CloudCredential>('/credentials/aws', data).then(r => r.data),

  createGCPCredential: (data: {
    cloud_account_id: string
    credential_type: 'gcp_workload_identity' | 'gcp_service_account_key'
    service_account_email?: string
    service_account_key?: string
  }) => api.post<CloudCredential>('/credentials/gcp', data).then(r => r.data),

  validate: (accountId: string) =>
    api.post<ValidationResult>(`/credentials/validate/${accountId}`).then(r => r.data),

  delete: (accountId: string) =>
    api.delete(`/credentials/${accountId}`),

  // Template downloads
  getAWSCloudFormationTemplate: () =>
    api.get<string>('/credentials/templates/aws/cloudformation', { responseType: 'text' }).then(r => r.data),

  getAWSTerraformTemplate: () =>
    api.get<string>('/credentials/templates/aws/terraform', { responseType: 'text' }).then(r => r.data),

  getGCPTerraformTemplate: () =>
    api.get<string>('/credentials/templates/gcp/terraform', { responseType: 'text' }).then(r => r.data),

  getGCPSetupScript: () =>
    api.get<string>('/credentials/templates/gcp/setup-script', { responseType: 'text' }).then(r => r.data),
}

// Gap acknowledgement API
export interface GapAcknowledgeResponse {
  message: string
  gap_id: string
  technique_id: string
  status: string
}

export interface AcceptRiskRequest {
  reason: string
}

export interface AcknowledgedGap {
  id: string
  technique_id: string
  technique_name: string
  tactic_id: string
  tactic_name: string
  status: 'acknowledged' | 'risk_accepted'
  priority: string
  reason: string | null
  remediation_notes: string | null
  risk_acceptance_reason: string | null
}

export interface AcknowledgedGapsResponse {
  gaps: AcknowledgedGap[]
  total: number
}

// Org-level acknowledged gap (includes cloud account info)
export interface OrgAcknowledgedGap {
  id: string
  technique_id: string
  technique_name: string
  tactic_id: string
  tactic_name: string
  status: 'acknowledged' | 'risk_accepted'
  priority: string
  cloud_account_id: string
  cloud_account_name: string | null
  reason: string | null
  remediation_notes: string | null
  risk_acceptance_reason: string | null
  acknowledged_at: string | null
  acknowledged_by_name: string | null
}

export interface OrgAcknowledgedGapsResponse {
  gaps: OrgAcknowledgedGap[]
  total: number
  by_status: {
    acknowledged: number
    risk_accepted: number
  }
}

export const gapsApi = {
  acknowledge: (techniqueId: string, cloudAccountId: string, notes?: string) =>
    api.post<GapAcknowledgeResponse>(
      `/gaps/${techniqueId}/acknowledge`,
      notes ? { notes } : {},
      { params: { cloud_account_id: cloudAccountId } }
    ).then(r => r.data),

  acceptRisk: (techniqueId: string, cloudAccountId: string, reason: string) =>
    api.post<GapAcknowledgeResponse>(
      `/gaps/${techniqueId}/accept-risk`,
      { reason },
      { params: { cloud_account_id: cloudAccountId } }
    ).then(r => r.data),

  reopen: (techniqueId: string, cloudAccountId: string) =>
    api.post<GapAcknowledgeResponse>(
      `/gaps/${techniqueId}/reopen`,
      {},
      { params: { cloud_account_id: cloudAccountId } }
    ).then(r => r.data),

  listAcknowledged: (cloudAccountId: string) =>
    api.get<{ acknowledged_technique_ids: string[]; count: number }>(
      '/gaps/acknowledged',
      { params: { cloud_account_id: cloudAccountId } }
    ).then(r => r.data),

  list: (cloudAccountId: string, status?: string) =>
    api.get<AcknowledgedGapsResponse>(
      '/gaps',
      { params: { cloud_account_id: cloudAccountId, status } }
    ).then(r => r.data),

  // Org-level endpoints for admins
  listOrgAcknowledged: () =>
    api.get<OrgAcknowledgedGapsResponse>('/gaps/org/acknowledged').then(r => r.data),

  reopenOrgGap: (gapId: string) =>
    api.post<GapAcknowledgeResponse>(`/gaps/org/${gapId}/reopen`, {}).then(r => r.data),
}

export default api
