/**
 * Auth Store Tests
 *
 * Tests for the Zustand authentication store, including:
 * - State management (setAuth, clearAuth, updateUser)
 * - Authentication actions (login, signup, logout)
 * - Session restoration and token refresh
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { useAuthStore, authActions } from './authStore'

// Reset the store before each test using the store's own clearAuth action
beforeEach(() => {
  const store = useAuthStore.getState()
  // Clear auth state
  store.clearAuth()
  // Reset initialised flag for initial state tests
  store.setInitialised(false)
})

describe('useAuthStore', () => {
  describe('initial state', () => {
    it('should have null values and false flags initially', () => {
      const state = useAuthStore.getState()

      expect(state.accessToken).toBeNull()
      expect(state.csrfToken).toBeNull()
      expect(state.user).toBeNull()
      expect(state.organization).toBeNull()
      expect(state.isAuthenticated).toBe(false)
      expect(state.isLoading).toBe(false)
      expect(state.isInitialised).toBe(false)
    })
  })

  describe('setAuth', () => {
    it('should set authentication data correctly', () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        full_name: 'Test User',
        mfa_enabled: false,
      }

      const mockOrg = {
        id: 'org-123',
        name: 'Test Org',
        slug: 'test-org',
        plan: 'free',
      }

      useAuthStore.getState().setAuth({
        accessToken: 'test-token',
        csrfToken: 'csrf-token',
        user: mockUser,
        organization: mockOrg,
      })

      const state = useAuthStore.getState()

      expect(state.accessToken).toBe('test-token')
      expect(state.csrfToken).toBe('csrf-token')
      expect(state.user).toEqual(mockUser)
      expect(state.organization).toEqual(mockOrg)
      expect(state.isAuthenticated).toBe(true)
      expect(state.isLoading).toBe(false)
      expect(state.isInitialised).toBe(true)
    })

    it('should clear legacy localStorage tokens', () => {
      localStorage.setItem('dcv_access_token', 'old-token')
      localStorage.setItem('dcv_refresh_token', 'old-refresh')

      useAuthStore.getState().setAuth({
        accessToken: 'new-token',
        user: {
          id: 'user-123',
          email: 'test@example.com',
          full_name: 'Test User',
          mfa_enabled: false,
        },
        organization: null,
      })

      expect(localStorage.getItem('dcv_access_token')).toBeNull()
      expect(localStorage.getItem('dcv_refresh_token')).toBeNull()
    })
  })

  describe('clearAuth', () => {
    it('should clear all authentication data', () => {
      // First set some auth data
      useAuthStore.getState().setAuth({
        accessToken: 'test-token',
        user: {
          id: 'user-123',
          email: 'test@example.com',
          full_name: 'Test User',
          mfa_enabled: false,
        },
        organization: {
          id: 'org-123',
          name: 'Test Org',
          slug: 'test-org',
          plan: 'free',
        },
      })

      // Then clear it
      useAuthStore.getState().clearAuth()

      const state = useAuthStore.getState()

      expect(state.accessToken).toBeNull()
      expect(state.csrfToken).toBeNull()
      expect(state.user).toBeNull()
      expect(state.organization).toBeNull()
      expect(state.isAuthenticated).toBe(false)
      expect(state.isInitialised).toBe(true) // Should remain true
    })

    it('should clear localStorage items', () => {
      localStorage.setItem('dcv_access_token', 'token')
      localStorage.setItem('dcv_refresh_token', 'refresh')
      localStorage.setItem('dcv-selected-account', 'account-123')

      useAuthStore.getState().clearAuth()

      expect(localStorage.getItem('dcv_access_token')).toBeNull()
      expect(localStorage.getItem('dcv_refresh_token')).toBeNull()
      expect(localStorage.getItem('dcv-selected-account')).toBeNull()
    })
  })

  describe('setLoading', () => {
    it('should set loading state', () => {
      useAuthStore.getState().setLoading(true)
      expect(useAuthStore.getState().isLoading).toBe(true)

      useAuthStore.getState().setLoading(false)
      expect(useAuthStore.getState().isLoading).toBe(false)
    })
  })

  describe('setInitialised', () => {
    it('should set initialised state', () => {
      useAuthStore.getState().setInitialised(true)
      expect(useAuthStore.getState().isInitialised).toBe(true)

      useAuthStore.getState().setInitialised(false)
      expect(useAuthStore.getState().isInitialised).toBe(false)
    })
  })

  describe('updateUser', () => {
    it('should update user fields while preserving others', () => {
      const initialUser = {
        id: 'user-123',
        email: 'test@example.com',
        full_name: 'Test User',
        mfa_enabled: false,
      }

      useAuthStore.getState().setAuth({
        accessToken: 'token',
        user: initialUser,
        organization: null,
      })

      useAuthStore.getState().updateUser({
        full_name: 'Updated Name',
        mfa_enabled: true,
      })

      const state = useAuthStore.getState()

      expect(state.user?.id).toBe('user-123')
      expect(state.user?.email).toBe('test@example.com')
      expect(state.user?.full_name).toBe('Updated Name')
      expect(state.user?.mfa_enabled).toBe(true)
    })

    it('should do nothing if no user exists', () => {
      useAuthStore.getState().updateUser({ full_name: 'New Name' })
      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('updateOrganization', () => {
    it('should replace organization', () => {
      const newOrg = {
        id: 'org-new',
        name: 'New Org',
        slug: 'new-org',
        plan: 'pro',
      }

      useAuthStore.getState().updateOrganization(newOrg)

      expect(useAuthStore.getState().organization).toEqual(newOrg)
    })
  })

  describe('setAccessToken', () => {
    it('should update access token', () => {
      useAuthStore.getState().setAccessToken('new-token')
      expect(useAuthStore.getState().accessToken).toBe('new-token')
    })
  })

  describe('setCsrfToken', () => {
    it('should update CSRF token', () => {
      useAuthStore.getState().setCsrfToken('new-csrf')
      expect(useAuthStore.getState().csrfToken).toBe('new-csrf')
    })
  })
})

describe('authActions', () => {
  describe('login', () => {
    it('should authenticate user and set auth state on successful login', async () => {
      const result = await authActions.login('test@example.com', 'password123', false)

      expect(result.requiresMfa).toBe(false)

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.accessToken).toBe('mock-access-token')
      expect(state.user?.email).toBe('test@example.com')
    })

    it('should return MFA requirement when MFA is needed', async () => {
      const result = await authActions.login('mfa@example.com', 'password123', false)

      expect(result.requiresMfa).toBe(true)
      expect(result.mfaToken).toBe('mock-mfa-token')

      // Auth state should not be set yet
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    })

    it('should throw error on invalid credentials', async () => {
      await expect(
        authActions.login('wrong@example.com', 'wrongpass', false)
      ).rejects.toThrow()
    })
  })

  describe('verifyMfa', () => {
    it('should complete MFA verification and set auth state', async () => {
      await authActions.verifyMfa('mock-mfa-token', '123456')

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.user?.mfa_enabled).toBe(true)
    })

    it('should throw error on invalid MFA code', async () => {
      await expect(
        authActions.verifyMfa('mock-mfa-token', '000000')
      ).rejects.toThrow()
    })
  })

  describe('signup', () => {
    it('should create account and set auth state', async () => {
      await authActions.signup(
        'new@example.com',
        'password123',
        'New User',
        'New Organization'
      )

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.user?.email).toBe('new@example.com')
      expect(state.user?.full_name).toBe('New User')
      expect(state.organization?.name).toBe('New Organization')
    })
  })

  describe('logout', () => {
    it('should clear auth state on logout', async () => {
      // First authenticate
      await authActions.login('test@example.com', 'password123', false)
      expect(useAuthStore.getState().isAuthenticated).toBe(true)

      // Then logout
      await authActions.logout()

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.accessToken).toBeNull()
      expect(state.user).toBeNull()
    })
  })

  describe('restoreSession', () => {
    it('should return false when no CSRF token exists', async () => {
      const result = await authActions.restoreSession()

      expect(result).toBe(false)
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().isInitialised).toBe(true)
    })
  })

  describe('refreshToken', () => {
    it('should return null when no CSRF token exists', async () => {
      const result = await authActions.refreshToken()

      expect(result).toBeNull()
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    })

    it('should refresh token when CSRF token exists in store', async () => {
      // Set up existing CSRF token
      useAuthStore.getState().setCsrfToken('existing-csrf')

      const result = await authActions.refreshToken()

      expect(result).toBe('mock-refreshed-token')
      expect(useAuthStore.getState().accessToken).toBe('mock-refreshed-token')
    })
  })
})
