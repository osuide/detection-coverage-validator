/**
 * Zustand Auth Store - Secure Token Management
 *
 * This store manages authentication state with security best practices:
 * - Access tokens stored in memory only (not localStorage)
 * - Refresh tokens stored in httpOnly cookies (set by backend)
 * - CSRF protection via double-submit cookie pattern
 *
 * On page refresh, the session is restored via the /refresh-session endpoint
 * which reads the httpOnly cookie automatically.
 */

import { create } from 'zustand'
import axios from 'axios'

// Types
export interface User {
  id: string
  email: string
  full_name: string
  avatar_url?: string | null
  timezone?: string
  email_verified?: boolean
  mfa_enabled: boolean
  created_at?: string
  role?: 'owner' | 'admin' | 'member' | 'viewer'
  identity_provider?: string
}

export interface Organization {
  id: string
  name: string
  slug: string
  logo_url?: string | null
  plan: string
  require_mfa?: boolean
  created_at?: string
}

interface AuthState {
  // State
  accessToken: string | null
  csrfToken: string | null
  user: User | null
  organization: Organization | null
  isAuthenticated: boolean
  isLoading: boolean
  isInitialised: boolean

  // Actions
  setAuth: (data: {
    accessToken: string
    csrfToken?: string
    user: User
    organization: Organization | null
  }) => void
  clearAuth: () => void
  setLoading: (loading: boolean) => void
  setInitialised: (initialised: boolean) => void
  updateUser: (user: Partial<User>) => void
  updateOrganization: (org: Organization) => void
  setAccessToken: (token: string) => void
  setCsrfToken: (token: string) => void
}

// API base URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

// Create axios instance with credentials (for cookies)
const authApi = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/auth`,
  withCredentials: true, // Critical: sends cookies with requests
  headers: {
    'Content-Type': 'application/json',
  },
})

// Helper to get CSRF token from cookie
function getCsrfTokenFromCookie(): string | null {
  const match = document.cookie.match(/dcv_csrf_token=([^;]+)/)
  return match ? match[1] : null
}

// Zustand store
export const useAuthStore = create<AuthState>((set, get) => ({
  // Initial state - all in memory, not persisted
  accessToken: null,
  csrfToken: null,
  user: null,
  organization: null,
  isAuthenticated: false,
  isLoading: false,
  isInitialised: false,

  // Set authentication data after login/signup
  setAuth: (data) => {
    // Clear any legacy localStorage tokens to prevent stale token issues
    try {
      localStorage.removeItem('dcv_access_token')
      localStorage.removeItem('dcv_refresh_token')
    } catch {
      // Ignore localStorage errors (e.g., in SSR or privacy mode)
    }

    set({
      accessToken: data.accessToken,
      csrfToken: data.csrfToken || getCsrfTokenFromCookie(),
      user: data.user,
      organization: data.organization,
      isAuthenticated: true,
      isLoading: false,
      isInitialised: true, // Mark as initialised after successful login
    })
  },

  // Clear all auth data on logout
  clearAuth: () => {
    // Also clear any legacy localStorage tokens to prevent stale token issues
    try {
      localStorage.removeItem('dcv_access_token')
      localStorage.removeItem('dcv_refresh_token')
    } catch {
      // Ignore localStorage errors (e.g., in SSR or privacy mode)
    }

    set({
      accessToken: null,
      csrfToken: null,
      user: null,
      organization: null,
      isAuthenticated: false,
      isLoading: false,
      isInitialised: true, // Keep initialised true so we don't re-fetch on logout
    })
  },

  setLoading: (loading) => set({ isLoading: loading }),
  setInitialised: (initialised) => set({ isInitialised: initialised }),

  updateUser: (userData) => {
    const currentUser = get().user
    if (currentUser) {
      set({ user: { ...currentUser, ...userData } })
    }
  },

  updateOrganization: (org) => set({ organization: org }),

  setAccessToken: (token) => set({ accessToken: token }),
  setCsrfToken: (token) => set({ csrfToken: token }),
}))

// Auth API functions that work with the store
export const authActions = {
  /**
   * Login with email and password
   */
  login: async (email: string, password: string, rememberMe: boolean = false) => {
    const response = await authApi.post('/login', {
      email,
      password,
      remember_me: rememberMe,
    })

    const data = response.data

    // Check if MFA is required
    if (data.requires_mfa) {
      return { requiresMfa: true, mfaToken: data.mfa_token }
    }

    // Set auth state (refresh token is in httpOnly cookie, set by backend)
    useAuthStore.getState().setAuth({
      accessToken: data.access_token,
      user: data.user,
      organization: data.organization,
    })

    return { requiresMfa: false }
  },

  /**
   * Complete MFA verification
   */
  verifyMfa: async (mfaToken: string, code: string) => {
    const response = await authApi.post('/login/mfa', {
      mfa_token: mfaToken,
      code,
    })

    const data = response.data

    useAuthStore.getState().setAuth({
      accessToken: data.access_token,
      user: data.user,
      organization: data.organization,
    })
  },

  /**
   * Sign up new user
   */
  signup: async (
    email: string,
    password: string,
    fullName: string,
    organizationName: string
  ) => {
    const response = await authApi.post('/signup', {
      email,
      password,
      full_name: fullName,
      organization_name: organizationName,
      terms_accepted: true,
    })

    const data = response.data

    useAuthStore.getState().setAuth({
      accessToken: data.access_token,
      user: data.user,
      organization: data.organization,
    })
  },

  /**
   * Restore session from httpOnly cookie on page load
   * This is called once when the app initialises
   */
  restoreSession: async (): Promise<boolean> => {
    const store = useAuthStore.getState()
    store.setLoading(true)

    try {
      // Get CSRF token from cookie (set during login)
      const csrfToken = getCsrfTokenFromCookie()

      if (!csrfToken) {
        // No CSRF token means no session
        store.setInitialised(true)
        store.setLoading(false)
        return false
      }

      // Try to refresh the session using the httpOnly cookie
      const response = await authApi.post(
        '/refresh-session',
        {},
        {
          headers: {
            'X-CSRF-Token': csrfToken,
          },
        }
      )

      const data = response.data

      // Get current user info
      const userResponse = await authApi.get('/me', {
        headers: {
          Authorization: `Bearer ${data.access_token}`,
        },
      })

      // Get user's organizations
      const orgsResponse = await authApi.get('/me/organizations', {
        headers: {
          Authorization: `Bearer ${data.access_token}`,
        },
      })

      const organizations = orgsResponse.data
      const organization = organizations.length > 0 ? organizations[0] : null

      store.setAuth({
        accessToken: data.access_token,
        csrfToken: data.csrf_token,
        user: userResponse.data,
        organization,
      })

      store.setInitialised(true)
      return true
    } catch {
      // Session restoration failed - user needs to log in
      store.clearAuth()
      store.setInitialised(true)
      return false
    }
  },

  /**
   * Refresh the access token using httpOnly cookie
   */
  refreshToken: async (): Promise<string | null> => {
    const store = useAuthStore.getState()
    const csrfToken = store.csrfToken || getCsrfTokenFromCookie()

    if (!csrfToken) {
      return null
    }

    try {
      const response = await authApi.post(
        '/refresh-session',
        {},
        {
          headers: {
            'X-CSRF-Token': csrfToken,
          },
        }
      )

      const data = response.data
      store.setAccessToken(data.access_token)
      store.setCsrfToken(data.csrf_token)

      return data.access_token
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
    const store = useAuthStore.getState()

    try {
      // Call backend to clear httpOnly cookie
      await authApi.post('/logout-session')
    } catch {
      // Ignore errors - we still clear local state
    }

    store.clearAuth()
  },

  /**
   * Get current user profile
   */
  getMe: async () => {
    const store = useAuthStore.getState()

    if (!store.accessToken) {
      throw new Error('Not authenticated')
    }

    const response = await authApi.get('/me', {
      headers: {
        Authorization: `Bearer ${store.accessToken}`,
      },
    })

    store.updateUser(response.data)
    return response.data
  },
}

// Create an axios instance that automatically handles token refresh
export const createAuthenticatedApi = (baseURL: string) => {
  const api = axios.create({
    baseURL: `${API_BASE_URL}${baseURL}`,
    withCredentials: true,
    headers: {
      'Content-Type': 'application/json',
    },
  })

  // Request interceptor - add auth header
  api.interceptors.request.use((config) => {
    const { accessToken } = useAuthStore.getState()
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`
    }
    return config
  })

  // Response interceptor - handle 401 and refresh token
  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config

      // If 401 and we haven't tried to refresh yet
      if (error.response?.status === 401 && !originalRequest._retry) {
        originalRequest._retry = true

        const newToken = await authActions.refreshToken()

        if (newToken) {
          originalRequest.headers.Authorization = `Bearer ${newToken}`
          return api(originalRequest)
        }
      }

      return Promise.reject(error)
    }
  )

  return api
}

export default useAuthStore
