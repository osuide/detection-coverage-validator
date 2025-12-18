import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { authApi, User, Organization, LoginResponse, SignupResponse } from '../services/authApi'

interface AuthState {
  user: User | null
  organization: Organization | null
  isAuthenticated: boolean
  isLoading: boolean
  accessToken: string | null
}

interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<LoginResponse>
  signup: (email: string, password: string, fullName: string, organizationName: string) => Promise<SignupResponse>
  logout: () => Promise<void>
  switchOrganization: (orgId: string) => Promise<void>
  refreshToken: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

const TOKEN_KEY = 'dcv_access_token'
const REFRESH_TOKEN_KEY = 'dcv_refresh_token'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    organization: null,
    isAuthenticated: false,
    isLoading: true,
    accessToken: null,
  })

  // Initialize auth state from stored tokens
  useEffect(() => {
    const initAuth = async () => {
      const accessToken = localStorage.getItem(TOKEN_KEY)
      const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)

      if (accessToken) {
        try {
          // Try to get current user info
          const user = await authApi.getMe(accessToken)
          const organizations = await authApi.getMyOrganizations(accessToken)

          setState({
            user,
            organization: organizations[0] || null,
            isAuthenticated: true,
            isLoading: false,
            accessToken,
          })
        } catch (error) {
          // Token expired, try to refresh
          if (refreshToken) {
            try {
              const response = await authApi.refresh(refreshToken)
              localStorage.setItem(TOKEN_KEY, response.access_token)
              localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh_token)

              const user = await authApi.getMe(response.access_token)
              const organizations = await authApi.getMyOrganizations(response.access_token)

              setState({
                user,
                organization: organizations[0] || null,
                isAuthenticated: true,
                isLoading: false,
                accessToken: response.access_token,
              })
            } catch {
              // Refresh failed, clear tokens
              localStorage.removeItem(TOKEN_KEY)
              localStorage.removeItem(REFRESH_TOKEN_KEY)
              setState({
                user: null,
                organization: null,
                isAuthenticated: false,
                isLoading: false,
                accessToken: null,
              })
            }
          } else {
            setState({
              user: null,
              organization: null,
              isAuthenticated: false,
              isLoading: false,
              accessToken: null,
            })
          }
        }
      } else {
        setState(prev => ({ ...prev, isLoading: false }))
      }
    }

    initAuth()
  }, [])

  const login = useCallback(async (email: string, password: string): Promise<LoginResponse> => {
    const response = await authApi.login(email, password)

    if (response.requires_mfa) {
      // Return response for MFA handling
      return response
    }

    // Store tokens
    localStorage.setItem(TOKEN_KEY, response.access_token)
    localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh_token)

    setState({
      user: response.user,
      organization: response.organization || null,
      isAuthenticated: true,
      isLoading: false,
      accessToken: response.access_token,
    })

    return response
  }, [])

  const signup = useCallback(async (
    email: string,
    password: string,
    fullName: string,
    organizationName: string
  ): Promise<SignupResponse> => {
    const response = await authApi.signup(email, password, fullName, organizationName)

    // Store tokens
    localStorage.setItem(TOKEN_KEY, response.access_token)
    localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh_token)

    setState({
      user: response.user,
      organization: response.organization,
      isAuthenticated: true,
      isLoading: false,
      accessToken: response.access_token,
    })

    return response
  }, [])

  const logout = useCallback(async () => {
    const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)

    if (refreshToken) {
      try {
        await authApi.logout(refreshToken)
      } catch {
        // Ignore logout errors
      }
    }

    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(REFRESH_TOKEN_KEY)

    setState({
      user: null,
      organization: null,
      isAuthenticated: false,
      isLoading: false,
      accessToken: null,
    })
  }, [])

  const switchOrganization = useCallback(async (orgId: string) => {
    if (!state.accessToken) return

    const response = await authApi.switchOrganization(state.accessToken, orgId)

    // Update access token with new org context
    localStorage.setItem(TOKEN_KEY, response.access_token)

    setState(prev => ({
      ...prev,
      organization: response.organization,
      accessToken: response.access_token,
    }))
  }, [state.accessToken])

  const refreshToken = useCallback(async () => {
    const storedRefreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
    if (!storedRefreshToken) return

    const response = await authApi.refresh(storedRefreshToken)

    localStorage.setItem(TOKEN_KEY, response.access_token)
    localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh_token)

    setState(prev => ({
      ...prev,
      accessToken: response.access_token,
    }))
  }, [])

  return (
    <AuthContext.Provider
      value={{
        ...state,
        login,
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
