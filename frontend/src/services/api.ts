import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'

const TOKEN_KEY = 'dcv_access_token'
const REFRESH_TOKEN_KEY = 'dcv_refresh_token'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add auth token interceptor
api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
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

      const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
      if (!refreshToken) {
        // No refresh token, redirect to login
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(REFRESH_TOKEN_KEY)
        window.location.href = '/login'
        return Promise.reject(error)
      }

      try {
        // Call refresh endpoint directly to avoid circular dependency
        const response = await axios.post(`${API_BASE_URL}/api/v1/auth/refresh`, {
          refresh_token: refreshToken,
        })

        const newAccessToken = response.data.access_token
        const newRefreshToken = response.data.refresh_token

        localStorage.setItem(TOKEN_KEY, newAccessToken)
        localStorage.setItem(REFRESH_TOKEN_KEY, newRefreshToken)

        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`
        processQueue(null, newAccessToken)

        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        // Refresh failed, clear tokens and redirect to login
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(REFRESH_TOKEN_KEY)
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
export interface CloudAccount {
  id: string
  name: string
  provider: 'aws' | 'gcp'
  account_id: string
  regions: string[]
  is_active: boolean
  last_scan_at: string | null
  created_at: string
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

export interface Gap {
  technique_id: string
  technique_name: string
  tactic_id: string
  tactic_name: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  reason: string
  data_sources: string[]
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
}

// API functions
export const accountsApi = {
  list: () => api.get<CloudAccount[]>('/accounts').then(r => r.data),
  get: (id: string) => api.get<CloudAccount>(`/accounts/${id}`).then(r => r.data),
  create: (data: Partial<CloudAccount>) => api.post<CloudAccount>('/accounts', data).then(r => r.data),
  delete: (id: string) => api.delete(`/accounts/${id}`),
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

export default api
