/**
 * OAuth State Store - Secure In-Memory Storage
 *
 * Stores OAuth PKCE parameters in memory only (not sessionStorage).
 * This prevents XSS attacks from stealing the code_verifier.
 *
 * Security: These values exist only in memory and are cleared:
 * - After successful token exchange
 * - On page close/refresh (memory is cleared)
 * - After 5 minutes (auto-expiry for abandoned flows)
 */

import { create } from 'zustand'

interface OAuthState {
  // OAuth flow parameters
  state: string | null
  codeVerifier: string | null
  provider: 'cognito' | 'github' | null

  // Timestamp for auto-expiry
  createdAt: number | null

  // Actions
  setOAuthParams: (params: {
    state: string
    codeVerifier?: string
    provider: 'cognito' | 'github'
  }) => void
  getAndClearParams: () => {
    state: string | null
    codeVerifier: string | null
    provider: 'cognito' | 'github' | null
  }
  clearParams: () => void
  isExpired: () => boolean
}

// OAuth flow should complete within 5 minutes
const OAUTH_FLOW_TIMEOUT_MS = 5 * 60 * 1000

export const useOAuthStore = create<OAuthState>((set, get) => ({
  state: null,
  codeVerifier: null,
  provider: null,
  createdAt: null,

  setOAuthParams: (params) => {
    set({
      state: params.state,
      codeVerifier: params.codeVerifier || null,
      provider: params.provider,
      createdAt: Date.now(),
    })
  },

  getAndClearParams: () => {
    const current = get()

    // Check if expired
    if (current.isExpired()) {
      set({
        state: null,
        codeVerifier: null,
        provider: null,
        createdAt: null,
      })
      return { state: null, codeVerifier: null, provider: null }
    }

    const params = {
      state: current.state,
      codeVerifier: current.codeVerifier,
      provider: current.provider,
    }

    // Clear after retrieval (one-time use)
    set({
      state: null,
      codeVerifier: null,
      provider: null,
      createdAt: null,
    })

    return params
  },

  clearParams: () => {
    set({
      state: null,
      codeVerifier: null,
      provider: null,
      createdAt: null,
    })
  },

  isExpired: () => {
    const { createdAt } = get()
    if (!createdAt) return true
    return Date.now() - createdAt > OAUTH_FLOW_TIMEOUT_MS
  },
}))

export default useOAuthStore
