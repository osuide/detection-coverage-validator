import axios from 'axios'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/api-keys`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface APIKey {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  ip_allowlist: string[] | null
  expires_at: string | null
  last_used_at: string | null
  last_used_ip: string | null
  usage_count: number
  is_active: boolean
  created_at: string
  created_by_name: string | null
}

export interface APIKeyCreated extends APIKey {
  key: string // Full key, only shown once
}

export interface CreateAPIKeyRequest {
  name: string
  scopes: string[]
  expires_days?: number
  ip_allowlist?: string[]
}

export interface UpdateAPIKeyRequest {
  name?: string
  scopes?: string[]
  ip_allowlist?: string[]
  is_active?: boolean
}

export interface ScopesResponse {
  scopes: string[]
  descriptions: Record<string, string>
}

// API functions
export const apiKeysApi = {
  // Get available scopes
  getScopes: async (token: string): Promise<ScopesResponse> => {
    const response = await api.get<ScopesResponse>('/scopes', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // List all API keys
  getAPIKeys: async (token: string): Promise<APIKey[]> => {
    const response = await api.get<APIKey[]>('', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Create new API key
  createAPIKey: async (token: string, data: CreateAPIKeyRequest): Promise<APIKeyCreated> => {
    const response = await api.post<APIKeyCreated>('', data, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Get single API key
  getAPIKey: async (token: string, keyId: string): Promise<APIKey> => {
    const response = await api.get<APIKey>(`/${keyId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Update API key
  updateAPIKey: async (token: string, keyId: string, data: UpdateAPIKeyRequest): Promise<APIKey> => {
    const response = await api.patch<APIKey>(`/${keyId}`, data, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Revoke API key
  revokeAPIKey: async (token: string, keyId: string): Promise<void> => {
    await api.delete(`/${keyId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  },
}

export default apiKeysApi
