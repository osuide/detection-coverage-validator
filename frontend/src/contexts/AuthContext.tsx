/**
 * AuthContext - React Context wrapper for Zustand auth store
 *
 * This provides backwards compatibility with components using the useAuth() hook
 * while internally using the secure Zustand store with httpOnly cookies.
 *
 * SECURITY IMPROVEMENTS:
 * - Refresh tokens stored in httpOnly cookies (XSS-proof)
 * - Access tokens stored in memory only (Zustand)
 * - CSRF protection via double-submit cookie pattern
 * - No localStorage usage for tokens
 * - Proactive token refresh before expiry (prevents unexpected logouts)
 */

import { createContext, useContext, useEffect, useCallback, ReactNode } from 'react'
import { useAuthStore, authActions, User, Organization } from '../stores/authStore'
import { authApi } from '../services/authApi'
import { useTokenRefresh } from '../hooks/useTokenRefresh'

// Types for backwards compatibility
interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: User
  organization: Organization | null
  requires_mfa: boolean
  mfa_token: string | null
}

interface SignupResponse {
  user: User
  organization: Organization
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

interface AuthContextType {
  user: User | null
  organization: Organization | null
  isAuthenticated: boolean
  isLoading: boolean
  accessToken: string | null
  token: string | null  // Alias for accessToken
  login: (email: string, password: string) => Promise<LoginResponse>
  loginWithMfa: (mfaToken: string, code: string) => Promise<void>
  signup: (email: string, password: string, fullName: string, organizationName: string) => Promise<SignupResponse>
  logout: () => Promise<void>
  switchOrganization: (orgId: string) => Promise<void>
  refreshToken: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  // Use Zustand store
  const {
    accessToken,
    user,
    organization,
    isAuthenticated,
    isLoading,
    isInitialised,
    setLoading,
    updateOrganization,
    setAccessToken,
  } = useAuthStore()

  // Initialise auth on mount - restore session from httpOnly cookie
  useEffect(() => {
    if (!isInitialised) {
      authActions.restoreSession()
    }
  }, [isInitialised])

  // Proactive token refresh - prevents unexpected logouts
  // This hook handles:
  // - Periodic refresh before token expiry (25 min intervals for 30 min tokens)
  // - Refresh on tab focus after being idle
  // - CSRF token sync across tabs
  // - Refresh when coming back online
  useTokenRefresh()

  // Login handler - uses secure cookie-based auth
  const login = useCallback(async (email: string, password: string): Promise<LoginResponse> => {
    setLoading(true)

    try {
      const result = await authActions.login(email, password)

      if (result.requiresMfa) {
        setLoading(false)
        // Return MFA required response (compatible with old interface)
        return {
          access_token: '',
          refresh_token: '',
          token_type: 'bearer',
          expires_in: 0,
          user: {} as User,
          organization: null,
          requires_mfa: true,
          mfa_token: result.mfaToken || null,
        }
      }

      // Get the updated state after login
      const state = useAuthStore.getState()

      return {
        access_token: state.accessToken || '',
        refresh_token: '', // Not exposed in secure mode
        token_type: 'bearer',
        expires_in: 1800, // 30 minutes
        user: state.user!,
        organization: state.organization,
        requires_mfa: false,
        mfa_token: null,
      }
    } catch (error) {
      setLoading(false)
      throw error
    }
  }, [setLoading])

  // MFA verification
  const loginWithMfa = useCallback(async (mfaToken: string, code: string): Promise<void> => {
    setLoading(true)
    try {
      await authActions.verifyMfa(mfaToken, code)
    } finally {
      setLoading(false)
    }
  }, [setLoading])

  // Signup handler
  const signup = useCallback(async (
    email: string,
    password: string,
    fullName: string,
    organizationName: string
  ): Promise<SignupResponse> => {
    setLoading(true)

    try {
      await authActions.signup(email, password, fullName, organizationName)

      const state = useAuthStore.getState()

      return {
        user: state.user!,
        organization: state.organization!,
        access_token: state.accessToken || '',
        refresh_token: '', // Not exposed in secure mode
        token_type: 'bearer',
        expires_in: 1800,
      }
    } catch (error) {
      setLoading(false)
      throw error
    }
  }, [setLoading])

  // Logout handler
  const logout = useCallback(async () => {
    await authActions.logout()
  }, [])

  // Switch organization
  const switchOrganization = useCallback(async (orgId: string) => {
    if (!accessToken) return

    const response = await authApi.switchOrganization(accessToken, orgId)

    // Update state with new org and token
    setAccessToken(response.access_token)
    updateOrganization(response.organization)
  }, [accessToken, setAccessToken, updateOrganization])

  // Refresh token
  const refreshToken = useCallback(async () => {
    await authActions.refreshToken()
  }, [])

  // Show loading state until initialised
  if (!isInitialised) {
    return (
      <AuthContext.Provider
        value={{
          user: null,
          organization: null,
          isAuthenticated: false,
          isLoading: true,
          accessToken: null,
          token: null,
          login,
          loginWithMfa,
          signup,
          logout,
          switchOrganization,
          refreshToken,
        }}
      >
        {children}
      </AuthContext.Provider>
    )
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        organization,
        isAuthenticated,
        isLoading,
        accessToken,
        token: accessToken, // Alias for convenience
        login,
        loginWithMfa,
        signup,
        logout,
        switchOrganization,
        refreshToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Re-export types for convenience
export type { User, Organization }
