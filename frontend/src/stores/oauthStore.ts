/**
 * OAuth State Store - Session Storage Backed
 *
 * Stores OAuth PKCE parameters in sessionStorage to survive OAuth redirects.
 * sessionStorage is used because:
 * - Tab-isolated (unlike localStorage) - prevents cross-tab leakage
 * - Survives same-tab navigation (unlike memory) - works with OAuth redirects
 * - Cleared on tab close - limits exposure window
 *
 * Security considerations:
 * - PKCE code_verifier is short-lived (5 min TTL) and one-time use
 * - Backend validates state via Redis (distributed CSRF protection)
 * - sessionStorage is the PKCE standard for browser SPAs
 *
 * Values are cleared:
 * - After successful token exchange (one-time use)
 * - On tab close (sessionStorage behaviour)
 * - After 5 minutes (TTL check on retrieval)
 */

import { create } from 'zustand'

// sessionStorage keys
const STORAGE_KEY = 'a13e_oauth_params'

interface StoredParams {
  state: string
  codeVerifier: string | null
  provider: 'cognito' | 'github'
  createdAt: number
}

interface OAuthState {
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
}

// OAuth flow should complete within 5 minutes
const OAUTH_FLOW_TIMEOUT_MS = 5 * 60 * 1000

// Helper to safely access sessionStorage
const getStoredParams = (): StoredParams | null => {
  try {
    const stored = sessionStorage.getItem(STORAGE_KEY)
    if (!stored) return null
    return JSON.parse(stored) as StoredParams
  } catch {
    return null
  }
}

const setStoredParams = (params: StoredParams | null): void => {
  try {
    if (params) {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(params))
    } else {
      sessionStorage.removeItem(STORAGE_KEY)
    }
  } catch {
    // Ignore storage errors (e.g., private browsing mode)
  }
}

export const useOAuthStore = create<OAuthState>(() => ({
  setOAuthParams: (params) => {
    setStoredParams({
      state: params.state,
      codeVerifier: params.codeVerifier || null,
      provider: params.provider,
      createdAt: Date.now(),
    })
  },

  getAndClearParams: () => {
    const stored = getStoredParams()

    // No stored params
    if (!stored) {
      return { state: null, codeVerifier: null, provider: null }
    }

    // Check if expired (5 minute TTL)
    if (Date.now() - stored.createdAt > OAUTH_FLOW_TIMEOUT_MS) {
      setStoredParams(null)
      return { state: null, codeVerifier: null, provider: null }
    }

    // Clear after retrieval (one-time use)
    setStoredParams(null)

    return {
      state: stored.state,
      codeVerifier: stored.codeVerifier,
      provider: stored.provider,
    }
  },

  clearParams: () => {
    setStoredParams(null)
  },
}))

export default useOAuthStore
