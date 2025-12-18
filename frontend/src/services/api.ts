import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

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

export const detectionsApi = {
  list: (params?: { cloud_account_id?: string; page?: number; limit?: number }) =>
    api.get<{ items: Detection[]; total: number }>('/detections', { params }).then(r => r.data),
}

export const coverageApi = {
  get: (accountId: string) => api.get<CoverageData>(`/coverage/${accountId}`).then(r => r.data),
  calculate: (accountId: string) => api.post<CoverageData>(`/coverage/${accountId}/calculate`).then(r => r.data),
}

export default api
