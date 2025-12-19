import axios from 'axios'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/auth/cognito`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface CognitoConfig {
  configured: boolean
  region?: string
  user_pool_id?: string
  client_id?: string
  domain?: string
  authorization_url?: string
  providers: string[]
}

export interface SSOInitiateResponse {
  authorization_url: string
  state: string
  code_verifier: string
}

export interface CognitoTokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: {
    id: string
    email: string
    full_name: string
    role: string
    mfa_enabled: boolean
    identity_provider?: string
  }
}

export interface FederatedIdentity {
  id: string
  provider: string
  provider_email?: string
  linked_at: string
  last_login_at?: string
}

// API functions
export const cognitoApi = {
  // Get Cognito configuration
  getConfig: async (): Promise<CognitoConfig> => {
    const response = await api.get<CognitoConfig>('/config')
    return response.data
  },

  // Initiate SSO flow
  initiateSso: async (provider: string, redirectUri: string): Promise<SSOInitiateResponse> => {
    const response = await api.get<SSOInitiateResponse>(`/authorize/${provider}`, {
      params: { redirect_uri: redirectUri },
    })
    return response.data
  },

  // Exchange code for tokens with PKCE
  exchangeToken: async (
    code: string,
    redirectUri: string,
    codeVerifier: string,
    state?: string
  ): Promise<CognitoTokenResponse> => {
    const response = await api.post<CognitoTokenResponse>('/token', {
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
      state,
    })
    return response.data
  },

  // List linked identities
  getLinkedIdentities: async (token: string): Promise<{ identities: FederatedIdentity[] }> => {
    const response = await api.get<{ identities: FederatedIdentity[] }>('/identities', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Unlink identity
  unlinkIdentity: async (token: string, provider: string): Promise<{ message: string }> => {
    const response = await api.delete<{ message: string }>(`/identities/${provider}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },
}

export default cognitoApi
