/**
 * Zustand Admin Auth Store - Secure Token Management
 *
 * This store manages admin authentication state with:
 * - Access tokens stored in memory only (not localStorage)
 * - Refresh tokens stored in localStorage (admin-specific)
 * - Automatic token refresh on 401 responses
 * - Session restoration on page load
 */

import { create } from 'zustand'
import axios, { AxiosError } from 'axios'

// Types
export interface AdminUser {
  id: string
  email: string
  full_name: string | null
  role: 'super_admin' | 'admin' | 'support'
  mfa_enabled: boolean
  requires_password_change: boolean
  permissions: string[]
}

interface AdminAuthState {
  // State
  accessToken: string | null
  refreshToken: string | null
  admin: AdminUser | null
  isAuthenticated: boolean
  isLoading: boolean
  isInitialised: boolean

  // Actions
  setAuth: (data: {
    accessToken: string
    refreshToken: string
    admin: AdminUser
  }) => void
  clearAuth: () => void
  setLoading: (loading: boolean) => void
  setInitialised: (initialised: boolean) => void
  updateAdmin: (admin: Partial<AdminUser>) => void
  setAccessToken: (token: string) => void
}

// API base URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

// Storage keys
const REFRESH_TOKEN_KEY = 'admin_refresh_token'

// Create axios instance for admin auth
const adminAuthApi = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/admin/auth`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Helper to get refresh token from localStorage
function getStoredRefreshToken(): string | null {
  try {
    return localStorage.getItem(REFRESH_TOKEN_KEY)
  } catch {
    return null
  }
}

// Helper to store refresh token
function storeRefreshToken(token: string): void {
  try {
    localStorage.setItem(REFRESH_TOKEN_KEY, token)
  } catch {
    // Ignore storage errors
  }
}

// Helper to clear refresh token
function clearStoredRefreshToken(): void {
  try {
    localStorage.removeItem(REFRESH_TOKEN_KEY)
    // Also clear legacy token key
    localStorage.removeItem('admin_token')
  } catch {
    // Ignore storage errors
  }
}

// Zustand store
export const useAdminAuthStore = create<AdminAuthState>((set, get) => ({
  // Initial state - access token in memory only
  accessToken: null,
  refreshToken: null,
  admin: null,
  isAuthenticated: false,
  isLoading: false,
  isInitialised: false,

  // Set authentication data after login
  setAuth: (data) => {
    // Clear legacy localStorage token
    clearStoredRefreshToken()
    // Store new refresh token
    storeRefreshToken(data.refreshToken)

    set({
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      admin: data.admin,
      isAuthenticated: true,
      isLoading: false,
      isInitialised: true,
    })
  },

  // Clear all auth data on logout
  clearAuth: () => {
    clearStoredRefreshToken()

    set({
      accessToken: null,
      refreshToken: null,
      admin: null,
      isAuthenticated: false,
      isLoading: false,
      isInitialised: true,
    })
  },

  setLoading: (loading) => set({ isLoading: loading }),
  setInitialised: (initialised) => set({ isInitialised: initialised }),

  updateAdmin: (adminData) => {
    const currentAdmin = get().admin
    if (currentAdmin) {
      set({ admin: { ...currentAdmin, ...adminData } })
    }
  },

  setAccessToken: (token) => set({ accessToken: token }),
}))

// Auth API functions that work with the store
export const adminAuthActions = {
  /**
   * Login with email and password
   */
  login: async (email: string, password: string) => {
    const response = await adminAuthApi.post('/login', { email, password })
    const data = response.data

    // Check if MFA is required
    if (data.requires_mfa) {
      return { requiresMfa: true, mfaToken: data.mfa_token }
    }

    // Fetch admin profile
    const profileResponse = await adminAuthApi.get('/me', {
      headers: { Authorization: `Bearer ${data.access_token}` },
    })

    // Set auth state
    useAdminAuthStore.getState().setAuth({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      admin: profileResponse.data,
    })

    return { requiresMfa: false }
  },

  /**
   * Complete MFA verification
   */
  verifyMfa: async (mfaToken: string, totpCode: string) => {
    const response = await adminAuthApi.post('/mfa/verify', {
      mfa_token: mfaToken,
      totp_code: totpCode,
    })

    const data = response.data

    useAdminAuthStore.getState().setAuth({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      admin: data.admin,
    })
  },

  /**
   * Restore session from stored refresh token on page load
   */
  restoreSession: async (): Promise<boolean> => {
    const store = useAdminAuthStore.getState()
    store.setLoading(true)

    try {
      const refreshToken = getStoredRefreshToken()

      if (!refreshToken) {
        store.setInitialised(true)
        store.setLoading(false)
        return false
      }

      // Try to refresh the access token
      const response = await adminAuthApi.post('/refresh', {
        refresh_token: refreshToken,
      })

      const data = response.data
      const newAccessToken = data.access_token

      // Fetch admin profile
      const profileResponse = await adminAuthApi.get('/me', {
        headers: { Authorization: `Bearer ${newAccessToken}` },
      })

      store.setAuth({
        accessToken: newAccessToken,
        refreshToken: refreshToken, // Keep using the same refresh token
        admin: profileResponse.data,
      })

      return true
    } catch {
      // Session restoration failed - clear stored token
      store.clearAuth()
      return false
    }
  },

  /**
   * Refresh the access token
   */
  refreshToken: async (): Promise<string | null> => {
    const store = useAdminAuthStore.getState()
    const refreshToken = store.refreshToken || getStoredRefreshToken()

    if (!refreshToken) {
      return null
    }

    try {
      const response = await adminAuthApi.post('/refresh', {
        refresh_token: refreshToken,
      })

      const newAccessToken = response.data.access_token
      store.setAccessToken(newAccessToken)

      return newAccessToken
    } catch {
      // Refresh failed - clear auth
      store.clearAuth()
      return null
    }
  },

  /**
   * Logout and clear session
   */
  logout: async () => {
    const store = useAdminAuthStore.getState()

    try {
      if (store.accessToken) {
        await adminAuthApi.post(
          '/logout',
          {},
          {
            headers: { Authorization: `Bearer ${store.accessToken}` },
          }
        )
      }
    } catch {
      // Ignore errors - we still clear local state
    }

    store.clearAuth()
  },

  /**
   * Get current admin profile
   */
  getMe: async () => {
    const store = useAdminAuthStore.getState()

    if (!store.accessToken) {
      throw new Error('Not authenticated')
    }

    const response = await adminAuthApi.get('/me', {
      headers: { Authorization: `Bearer ${store.accessToken}` },
    })

    store.updateAdmin(response.data)
    return response.data
  },
}

// Create an axios instance that automatically handles token refresh
export const createAdminAuthenticatedApi = (baseURL: string) => {
  const api = axios.create({
    baseURL: `${API_BASE_URL}${baseURL}`,
    headers: {
      'Content-Type': 'application/json',
    },
  })

  // Request interceptor - add auth header
  api.interceptors.request.use((config) => {
    const { accessToken } = useAdminAuthStore.getState()
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`
    }
    return config
  })

  // Response interceptor - handle 401 and refresh token
  api.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const originalRequest = error.config as typeof error.config & { _retry?: boolean }

      // If 401 and we haven't tried to refresh yet
      if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
        originalRequest._retry = true

        const newToken = await adminAuthActions.refreshToken()

        if (newToken && originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newToken}`
          return api(originalRequest)
        }
      }

      return Promise.reject(error)
    }
  )

  return api
}

// Pre-configured admin API instance
export const adminApi = createAdminAuthenticatedApi('/api/v1/admin')

export default useAdminAuthStore
