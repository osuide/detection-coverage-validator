/**
 * GitHub OAuth API service for direct authentication (bypassing Cognito).
 */

import axios from 'axios'
import type { User, Organization } from '../stores/authStore'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export interface GitHubConfig {
  enabled: boolean
  client_id: string | null
}

export interface GitHubAuthorizeResponse {
  authorization_url: string
  state: string
}

export interface GitHubTokenResponse {
  access_token: string
  refresh_token: string
  csrf_token: string
  expires_in: number
  user: User
  organization: Organization
}

export const githubApi = {
  /**
   * Get GitHub OAuth configuration.
   */
  async getConfig(): Promise<GitHubConfig> {
    const response = await api.get<GitHubConfig>('/api/v1/auth/github/config')
    return response.data
  },

  /**
   * Get GitHub authorization URL.
   */
  async authorize(redirectUri: string): Promise<GitHubAuthorizeResponse> {
    const response = await api.get<GitHubAuthorizeResponse>('/api/v1/auth/github/authorize', {
      params: { redirect_uri: redirectUri },
    })
    return response.data
  },

  /**
   * Exchange authorization code for tokens.
   */
  async exchangeToken(
    code: string,
    redirectUri: string,
    state: string
  ): Promise<GitHubTokenResponse> {
    const response = await api.post<GitHubTokenResponse>('/api/v1/auth/github/token', {
      code,
      redirect_uri: redirectUri,
      state,
    })
    return response.data
  },
}
