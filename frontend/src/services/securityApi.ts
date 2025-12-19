import axios from 'axios'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/org`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface SecuritySettings {
  id: string
  organization_id: string
  require_mfa: boolean
  mfa_grace_period_days: number
  session_timeout_minutes: number
  idle_timeout_minutes: number
  allowed_auth_methods: string[]
  password_min_length: number
  password_require_uppercase: boolean
  password_require_lowercase: boolean
  password_require_number: boolean
  password_require_special: boolean
  max_failed_login_attempts: number
  lockout_duration_minutes: number
  ip_allowlist: string[] | null
  created_at: string
  updated_at: string
}

export interface SecuritySettingsUpdate {
  require_mfa?: boolean
  mfa_grace_period_days?: number
  session_timeout_minutes?: number
  idle_timeout_minutes?: number
  allowed_auth_methods?: string[]
  password_min_length?: number
  password_require_uppercase?: boolean
  password_require_lowercase?: boolean
  password_require_number?: boolean
  password_require_special?: boolean
  max_failed_login_attempts?: number
  lockout_duration_minutes?: number
  ip_allowlist?: string[] | null
}

export interface VerifiedDomain {
  id: string
  domain: string
  verification_token?: string
  verification_method?: string
  verified_at?: string
  auto_join_enabled: boolean
  sso_required: boolean
  created_at: string
}

export interface DomainVerificationInfo {
  verified: boolean
  verification_method?: string
  instructions?: string
  record_type?: string
  record_name?: string
  record_value?: string
  message?: string
}

// API functions
export const securityApi = {
  // Get security settings
  getSettings: async (token: string): Promise<SecuritySettings> => {
    const response = await api.get<SecuritySettings>('/security', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Update security settings
  updateSettings: async (token: string, updates: SecuritySettingsUpdate): Promise<SecuritySettings> => {
    const response = await api.put<SecuritySettings>('/security', updates, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // List verified domains
  getDomains: async (token: string): Promise<VerifiedDomain[]> => {
    const response = await api.get<VerifiedDomain[]>('/domains', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Add domain for verification
  addDomain: async (token: string, domain: string, verificationMethod: string = 'dns_txt'): Promise<VerifiedDomain> => {
    const response = await api.post<VerifiedDomain>('/domains', {
      domain,
      verification_method: verificationMethod,
    }, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Get domain verification info
  getDomainVerificationInfo: async (token: string, domainId: string): Promise<DomainVerificationInfo> => {
    const response = await api.get<DomainVerificationInfo>(`/domains/${domainId}/verify`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Confirm domain verification
  confirmDomainVerification: async (token: string, domainId: string): Promise<DomainVerificationInfo> => {
    const response = await api.post<DomainVerificationInfo>(`/domains/${domainId}/verify`, {}, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Update domain settings
  updateDomain: async (
    token: string,
    domainId: string,
    updates: { auto_join_enabled?: boolean; sso_required?: boolean }
  ): Promise<VerifiedDomain> => {
    const response = await api.patch<VerifiedDomain>(`/domains/${domainId}`, updates, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Remove domain
  removeDomain: async (token: string, domainId: string): Promise<void> => {
    await api.delete(`/domains/${domainId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  },
}

export default securityApi
