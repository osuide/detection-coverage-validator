/**
 * Zustand Admin Auth Store - Secure Token Management
 *
 * This store manages admin authentication state with:
 * - Access tokens stored in memory only (not localStorage)
 * - Refresh tokens stored in httpOnly cookies (secure against XSS)
 * - CSRF token stored in memory for double-submit pattern
 * - Automatic token refresh on 401 responses
 * - Session restoration on page load
 *
 * Security: Refresh tokens are now httpOnly cookies, not localStorage.
 * This prevents XSS attacks from stealing admin credentials.
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
  csrfToken: string | null // CSRF token for double-submit pattern
  admin: AdminUser | null
  isAuthenticated: boolean
  isLoading: boolean
  isInitialised: boolean

  // Actions
  setAuth: (data: {
    accessToken: string
    csrfToken: string
    admin: AdminUser
  }) => void
  clearAuth: () => void
  setLoading: (loading: boolean) => void
  setInitialised: (initialised: boolean) => void
  updateAdmin: (admin: Partial<AdminUser>) => void
  setAccessToken: (token: string) => void
  setCsrfToken: (token: string) => void
}

// API base URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

// Cookie name for CSRF token (readable by JS, unlike refresh token)
const ADMIN_CSRF_COOKIE_NAME = 'dcv_admin_csrf_token'

// Create axios instance for admin auth
// withCredentials: true ensures cookies are sent with requests
const adminAuthApi = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/admin/auth`,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Critical: send httpOnly cookies with requests
})

// Helper to get CSRF token from cookie
function getCsrfTokenFromCookie(): string | null {
  try {
    const cookies = document.cookie.split(';')
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=')
      if (name === ADMIN_CSRF_COOKIE_NAME) {
        return decodeURIComponent(value)
      }
    }
    return null
  } catch {
    return null
  }
}

// Helper to clear legacy localStorage tokens (migration cleanup)
function clearLegacyStorage(): void {
  try {
    localStorage.removeItem('admin_refresh_token')
    localStorage.removeItem('admin_token')
  } catch {
    // Ignore storage errors
  }
}

// Zustand store
export const useAdminAuthStore = create<AdminAuthState>((set, get) => ({
  // Initial state - tokens in memory only (refresh token in httpOnly cookie)
  accessToken: null,
  csrfToken: null,
  admin: null,
  isAuthenticated: false,
  isLoading: false,
  isInitialised: false,

  // Set authentication data after login
  setAuth: (data) => {
    // Clear legacy localStorage tokens (migration cleanup)
    clearLegacyStorage()

    set({
      accessToken: data.accessToken,
      csrfToken: data.csrfToken,
      admin: data.admin,
      isAuthenticated: true,
      isLoading: false,
      isInitialised: true,
    })
  },

  // Clear all auth data on logout
  clearAuth: () => {
    // Clear legacy localStorage tokens
    clearLegacyStorage()

    set({
      accessToken: null,
      csrfToken: null,
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
  setCsrfToken: (token) => set({ csrfToken: token }),
}))

// Auth API functions that work with the store
export const adminAuthActions = {
  /**
   * Login with email and password
   * Security: Refresh token is set as httpOnly cookie by the server
   */
  login: async (email: string, password: string) => {
    const response = await adminAuthApi.post('/login', { email, password })
    const data = response.data

    // Check if MFA setup is required (first-time login in staging/prod)
    if (data.mfa_setup_required) {
      return {
        requiresMfa: false,
        mfaSetupRequired: true,
        setupToken: data.setup_token,
      }
    }

    // Check if MFA verification is required
    if (data.requires_mfa) {
      return { requiresMfa: true, mfaToken: data.mfa_token }
    }

    // Fetch admin profile
    const profileResponse = await adminAuthApi.get('/me', {
      headers: { Authorization: `Bearer ${data.access_token}` },
    })

    // Set auth state (refresh token is in httpOnly cookie, not response body)
    useAdminAuthStore.getState().setAuth({
      accessToken: data.access_token,
      csrfToken: data.csrf_token,
      admin: profileResponse.data,
    })

    return { requiresMfa: false, mfaSetupRequired: false }
  },

  /**
   * Complete MFA verification
   * Security: Refresh token is set as httpOnly cookie by the server
   */
  verifyMfa: async (mfaToken: string, totpCode: string) => {
    const response = await adminAuthApi.post('/mfa/verify', {
      mfa_token: mfaToken,
      totp_code: totpCode,
    })

    const data = response.data

    useAdminAuthStore.getState().setAuth({
      accessToken: data.access_token,
      csrfToken: data.csrf_token,
      admin: data.admin,
    })
  },

  /**
   * Restore session from httpOnly cookie on page load
   * Security: Refresh token is read from httpOnly cookie by server,
   * CSRF token is read from readable cookie for double-submit pattern
   */
  restoreSession: async (): Promise<boolean> => {
    const store = useAdminAuthStore.getState()
    store.setLoading(true)

    try {
      // Get CSRF token from cookie (set by server on previous login)
      const csrfToken = getCsrfTokenFromCookie()

      if (!csrfToken) {
        // No CSRF token means no session to restore
        store.setInitialised(true)
        store.setLoading(false)
        return false
      }

      // Try to refresh the access token
      // httpOnly cookie with refresh token is sent automatically
      // CSRF token is sent in header for double-submit validation
      const response = await adminAuthApi.post(
        '/refresh',
        {},
        {
          headers: {
            'X-Admin-CSRF-Token': csrfToken,
          },
        }
      )

      const data = response.data
      const newAccessToken = data.access_token

      // Fetch admin profile
      const profileResponse = await adminAuthApi.get('/me', {
        headers: { Authorization: `Bearer ${newAccessToken}` },
      })

      store.setAuth({
        accessToken: newAccessToken,
        csrfToken: csrfToken, // CSRF token remains in cookie
        admin: profileResponse.data,
      })

      return true
    } catch {
      // Session restoration failed - clear auth state
      store.clearAuth()
      return false
    }
  },

  /**
   * Refresh the access token
   * Security: Uses httpOnly cookie for refresh token, CSRF for validation
   */
  refreshToken: async (): Promise<string | null> => {
    const store = useAdminAuthStore.getState()
    const csrfToken = store.csrfToken || getCsrfTokenFromCookie()

    if (!csrfToken) {
      return null
    }

    try {
      // Refresh token is in httpOnly cookie, sent automatically
      // CSRF token is sent in header for validation
      const response = await adminAuthApi.post(
        '/refresh',
        {},
        {
          headers: {
            'X-Admin-CSRF-Token': csrfToken,
          },
        }
      )

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
   * Server clears httpOnly cookies
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

  /**
   * Start MFA setup - get provisioning URI for QR code
   */
  setupMFA: async (): Promise<{ provisioning_uri: string; secret: string }> => {
    const store = useAdminAuthStore.getState()

    if (!store.accessToken) {
      throw new Error('Not authenticated')
    }

    const response = await adminAuthApi.post(
      '/auth/mfa/setup',
      {},
      { headers: { Authorization: `Bearer ${store.accessToken}` } }
    )
    return response.data
  },

  /**
   * Enable MFA after verifying TOTP code
   */
  enableMFA: async (totpCode: string): Promise<void> => {
    const store = useAdminAuthStore.getState()

    if (!store.accessToken) {
      throw new Error('Not authenticated')
    }

    await adminAuthApi.post(
      '/auth/mfa/enable',
      { totp_code: totpCode },
      { headers: { Authorization: `Bearer ${store.accessToken}` } }
    )

    // Update local state to reflect MFA is now enabled
    store.updateAdmin({ mfa_enabled: true })
  },

  /**
   * Start MFA setup using setup token (for first-time setup)
   */
  setupMFAWithToken: async (
    setupToken: string
  ): Promise<{ provisioning_uri: string; secret: string }> => {
    const response = await adminAuthApi.post('/mfa/setup-with-token', {
      setup_token: setupToken,
    })
    return response.data
  },

  /**
   * Enable MFA and complete login using setup token
   * Security: Refresh token is set as httpOnly cookie by server
   */
  enableMFAWithToken: async (setupToken: string, totpCode: string): Promise<void> => {
    const response = await adminAuthApi.post('/mfa/enable-with-token', {
      setup_token: setupToken,
      totp_code: totpCode,
    })

    const data = response.data

    // Set auth state - user is now fully logged in
    // Refresh token is in httpOnly cookie, not response body
    useAdminAuthStore.getState().setAuth({
      accessToken: data.access_token,
      csrfToken: data.csrf_token,
      admin: data.admin,
    })
  },

  /**
   * Get WebAuthn authentication options for login
   */
  getWebAuthnLoginOptions: async (
    email: string
  ): Promise<{ options: unknown; auth_token: string }> => {
    const response = await adminAuthApi.post('/webauthn/auth/options', { email })
    return response.data
  },

  /**
   * Complete WebAuthn login with credential response
   * Security: Refresh token is set as httpOnly cookie by server
   */
  verifyWebAuthnLogin: async (authToken: string, credential: unknown): Promise<void> => {
    const response = await adminAuthApi.post('/webauthn/auth/verify', {
      auth_token: authToken,
      credential,
    })

    const data = response.data

    // Refresh token is in httpOnly cookie, not response body
    useAdminAuthStore.getState().setAuth({
      accessToken: data.access_token,
      csrfToken: data.csrf_token,
      admin: data.admin,
    })
  },

  /**
   * Get WebAuthn registration options for adding a new key
   * Note: Uses adminApi (not adminAuthApi) as WebAuthn routes are at /admin/webauthn, not /admin/auth/webauthn
   */
  getWebAuthnRegisterOptions: async (
    deviceName: string,
    authenticatorType?: string
  ): Promise<{ options: unknown }> => {
    const store = useAdminAuthStore.getState()

    if (!store.accessToken) {
      throw new Error('Not authenticated')
    }

    // Create a one-off request with the correct base URL
    const response = await axios.post(
      `${API_BASE_URL}/api/v1/admin/webauthn/register/options`,
      { device_name: deviceName, authenticator_type: authenticatorType },
      { headers: { Authorization: `Bearer ${store.accessToken}` } }
    )
    return response.data
  },

  /**
   * Verify WebAuthn registration
   * Note: Uses adminApi (not adminAuthApi) as WebAuthn routes are at /admin/webauthn, not /admin/auth/webauthn
   */
  verifyWebAuthnRegister: async (credential: unknown, deviceName: string): Promise<void> => {
    const store = useAdminAuthStore.getState()

    if (!store.accessToken) {
      throw new Error('Not authenticated')
    }

    await axios.post(
      `${API_BASE_URL}/api/v1/admin/webauthn/register/verify`,
      { credential, device_name: deviceName },
      { headers: { Authorization: `Bearer ${store.accessToken}` } }
    )

    // Update MFA status
    store.updateAdmin({ mfa_enabled: true })
  },
}

// Create an axios instance that automatically handles token refresh
export const createAdminAuthenticatedApi = (baseURL: string) => {
  const api = axios.create({
    baseURL: `${API_BASE_URL}${baseURL}`,
    headers: {
      'Content-Type': 'application/json',
    },
    withCredentials: true, // Send httpOnly cookies with requests
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
