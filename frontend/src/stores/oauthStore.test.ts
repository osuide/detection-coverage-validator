/**
 * OAuth Store Unit Tests
 *
 * Tests for sessionStorage-backed OAuth state management.
 * sessionStorage is used to survive OAuth redirects while maintaining
 * tab isolation and automatic cleanup on tab close.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useOAuthStore } from './oauthStore'

const STORAGE_KEY = 'a13e_oauth_params'

describe('oauthStore', () => {
  beforeEach(() => {
    // Clear sessionStorage before each test
    sessionStorage.clear()
    // Reset timers
    vi.useRealTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    sessionStorage.clear()
  })

  describe('setOAuthParams', () => {
    it('should store OAuth parameters for Cognito flow', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'test-state-123',
        codeVerifier: 'test-code-verifier-456',
        provider: 'cognito',
      })

      const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '{}')
      expect(stored.state).toBe('test-state-123')
      expect(stored.codeVerifier).toBe('test-code-verifier-456')
      expect(stored.provider).toBe('cognito')
      expect(stored.createdAt).toBeGreaterThan(0)
    })

    it('should store OAuth parameters for GitHub flow (no codeVerifier)', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'github-state-789',
        provider: 'github',
      })

      const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '{}')
      expect(stored.state).toBe('github-state-789')
      expect(stored.codeVerifier).toBeNull()
      expect(stored.provider).toBe('github')
    })

    it('should overwrite previous OAuth parameters', () => {
      const store = useOAuthStore.getState()

      // Set initial params
      store.setOAuthParams({
        state: 'first-state',
        codeVerifier: 'first-verifier',
        provider: 'cognito',
      })

      // Overwrite with new params
      store.setOAuthParams({
        state: 'second-state',
        codeVerifier: 'second-verifier',
        provider: 'cognito',
      })

      const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '{}')
      expect(stored.state).toBe('second-state')
      expect(stored.codeVerifier).toBe('second-verifier')
    })
  })

  describe('getAndClearParams', () => {
    it('should return stored params and clear them', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'test-state',
        codeVerifier: 'test-verifier',
        provider: 'cognito',
      })

      const params = store.getAndClearParams()

      expect(params.state).toBe('test-state')
      expect(params.codeVerifier).toBe('test-verifier')
      expect(params.provider).toBe('cognito')

      // Verify params are cleared from sessionStorage
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
    })

    it('should return null values when no params are stored', () => {
      const store = useOAuthStore.getState()
      const params = store.getAndClearParams()

      expect(params.state).toBeNull()
      expect(params.codeVerifier).toBeNull()
      expect(params.provider).toBeNull()
    })

    it('should only allow one-time retrieval', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'one-time-state',
        codeVerifier: 'one-time-verifier',
        provider: 'cognito',
      })

      // First retrieval
      const firstParams = store.getAndClearParams()
      expect(firstParams.state).toBe('one-time-state')

      // Second retrieval should return nulls
      const secondParams = useOAuthStore.getState().getAndClearParams()
      expect(secondParams.state).toBeNull()
      expect(secondParams.codeVerifier).toBeNull()
    })
  })

  describe('clearParams', () => {
    it('should clear all stored params', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'test-state',
        codeVerifier: 'test-verifier',
        provider: 'cognito',
      })

      store.clearParams()

      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
    })
  })

  describe('expiry handling', () => {
    it('should return nulls for expired params (after 5 minutes)', () => {
      vi.useFakeTimers()

      const store = useOAuthStore.getState()
      store.setOAuthParams({
        state: 'expired-state',
        codeVerifier: 'expired-verifier',
        provider: 'cognito',
      })

      // Fast-forward 6 minutes
      vi.advanceTimersByTime(6 * 60 * 1000)

      const params = useOAuthStore.getState().getAndClearParams()

      expect(params.state).toBeNull()
      expect(params.codeVerifier).toBeNull()
      expect(params.provider).toBeNull()
    })

    it('should return params before 5 minutes', () => {
      vi.useFakeTimers()

      const store = useOAuthStore.getState()
      store.setOAuthParams({
        state: 'valid-state',
        codeVerifier: 'valid-verifier',
        provider: 'cognito',
      })

      // Fast-forward 4 minutes 59 seconds
      vi.advanceTimersByTime(4 * 60 * 1000 + 59 * 1000)

      const params = useOAuthStore.getState().getAndClearParams()

      expect(params.state).toBe('valid-state')
      expect(params.codeVerifier).toBe('valid-verifier')
    })

    it('should clear expired params from sessionStorage', () => {
      vi.useFakeTimers()

      const store = useOAuthStore.getState()
      store.setOAuthParams({
        state: 'expired-state',
        provider: 'github',
      })

      // Fast-forward 6 minutes
      vi.advanceTimersByTime(6 * 60 * 1000)

      // Retrieve (should be expired)
      store.getAndClearParams()

      // sessionStorage should be cleared
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
    })
  })

  describe('storage behaviour', () => {
    it('should use sessionStorage (survives same-tab navigation)', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'navigation-test',
        codeVerifier: 'nav-verifier',
        provider: 'cognito',
      })

      // Verify it's in sessionStorage
      expect(sessionStorage.getItem(STORAGE_KEY)).not.toBeNull()

      // Simulate what happens after OAuth redirect (new store instance reads from sessionStorage)
      const params = useOAuthStore.getState().getAndClearParams()
      expect(params.state).toBe('navigation-test')
      expect(params.codeVerifier).toBe('nav-verifier')
    })

    it('should NOT persist to localStorage', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'secret-state',
        codeVerifier: 'secret-verifier',
        provider: 'cognito',
      })

      // localStorage should not have any OAuth data
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull()
      expect(localStorage.getItem('oauth_state')).toBeNull()
      expect(localStorage.getItem('oauth_code_verifier')).toBeNull()
    })

    it('should handle sessionStorage errors gracefully', () => {
      // Use vi.spyOn to properly mock sessionStorage methods
      const setItemSpy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('QuotaExceededError')
      })
      const getItemSpy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('SecurityError')
      })

      const store = useOAuthStore.getState()

      // Should not throw when setItem fails
      expect(() => {
        store.setOAuthParams({
          state: 'error-test',
          provider: 'github',
        })
      }).not.toThrow()

      // Should return nulls when getItem fails
      const params = store.getAndClearParams()
      expect(params.state).toBeNull()
      expect(params.codeVerifier).toBeNull()
      expect(params.provider).toBeNull()

      // Restore mocks
      setItemSpy.mockRestore()
      getItemSpy.mockRestore()
    })
  })
})
