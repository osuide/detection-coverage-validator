import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1/auth',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface User {
  id: string
  email: string
  full_name: string
  avatar_url: string | null
  timezone: string
  email_verified: boolean
  mfa_enabled: boolean
  created_at: string
}

export interface Organization {
  id: string
  name: string
  slug: string
  logo_url: string | null
  plan: string
  require_mfa: boolean
  created_at: string
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: User
  organization: Organization | null
  requires_mfa: boolean
  mfa_token: string | null
}

export interface SignupResponse {
  user: User
  organization: Organization
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export interface RefreshResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export interface SwitchOrganizationResponse {
  access_token: string
  organization: Organization
}

export interface MFASetupResponse {
  secret: string
  provisioning_uri: string
  qr_code_base64?: string
}

export interface MFABackupCodesResponse {
  backup_codes: string[]
}

export interface Session {
  id: string
  user_agent: string | null
  ip_address: string | null
  location: string | null
  is_current: boolean
  last_activity_at: string
  created_at: string
}

// Auth API functions
export const authApi = {
  login: async (email: string, password: string): Promise<LoginResponse> => {
    const response = await api.post<LoginResponse>('/login', { email, password })
    return response.data
  },

  loginWithMFA: async (mfaToken: string, code: string): Promise<LoginResponse> => {
    const response = await api.post<LoginResponse>('/login/mfa', { mfa_token: mfaToken, code })
    return response.data
  },

  signup: async (
    email: string,
    password: string,
    fullName: string,
    organizationName: string
  ): Promise<SignupResponse> => {
    const response = await api.post<SignupResponse>('/signup', {
      email,
      password,
      full_name: fullName,
      organization_name: organizationName,
      terms_accepted: true,
    })
    return response.data
  },

  logout: async (refreshToken: string): Promise<void> => {
    await api.post('/logout', { refresh_token: refreshToken })
  },

  refresh: async (refreshToken: string): Promise<RefreshResponse> => {
    const response = await api.post<RefreshResponse>('/refresh', { refresh_token: refreshToken })
    return response.data
  },

  forgotPassword: async (email: string): Promise<void> => {
    await api.post('/forgot-password', { email })
  },

  resetPassword: async (token: string, password: string): Promise<void> => {
    await api.post('/reset-password', { token, password })
  },

  getMe: async (token: string): Promise<User> => {
    const response = await api.get<User>('/me', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  updateMe: async (
    token: string,
    data: { full_name?: string; timezone?: string; avatar_url?: string }
  ): Promise<User> => {
    const response = await api.patch<User>('/me', data, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  changePassword: async (
    token: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> => {
    await api.post(
      '/me/change-password',
      { current_password: currentPassword, new_password: newPassword },
      { headers: { Authorization: `Bearer ${token}` } }
    )
  },

  // MFA
  setupMFA: async (token: string): Promise<MFASetupResponse> => {
    const response = await api.post<MFASetupResponse>(
      '/me/mfa/setup',
      {},
      { headers: { Authorization: `Bearer ${token}` } }
    )
    return response.data
  },

  verifyMFASetup: async (token: string, code: string): Promise<MFABackupCodesResponse> => {
    const response = await api.post<MFABackupCodesResponse>(
      '/me/mfa/verify',
      { code },
      { headers: { Authorization: `Bearer ${token}` } }
    )
    return response.data
  },

  disableMFA: async (token: string): Promise<void> => {
    await api.delete('/me/mfa', { headers: { Authorization: `Bearer ${token}` } })
  },

  // Organizations
  getMyOrganizations: async (token: string): Promise<Organization[]> => {
    const response = await api.get<Organization[]>('/me/organizations', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  switchOrganization: async (token: string, orgId: string): Promise<SwitchOrganizationResponse> => {
    const response = await api.post<SwitchOrganizationResponse>(
      '/me/organizations/switch',
      { organization_id: orgId },
      { headers: { Authorization: `Bearer ${token}` } }
    )
    return response.data
  },

  createOrganization: async (
    token: string,
    name: string,
    slug: string
  ): Promise<Organization> => {
    const response = await api.post<Organization>(
      '/organizations',
      { name, slug },
      { headers: { Authorization: `Bearer ${token}` } }
    )
    return response.data
  },

  checkSlugAvailability: async (slug: string): Promise<boolean> => {
    const response = await api.get<{ available: boolean }>('/organizations/check-slug', {
      params: { slug },
    })
    return response.data.available
  },

  // Sessions
  getSessions: async (token: string): Promise<Session[]> => {
    const response = await api.get<Session[]>('/me/sessions', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  revokeSession: async (token: string, sessionId: string): Promise<void> => {
    await api.delete(`/me/sessions/${sessionId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  },

  revokeAllSessions: async (token: string): Promise<void> => {
    await api.delete('/me/sessions', { headers: { Authorization: `Bearer ${token}` } })
  },
}

export default authApi
