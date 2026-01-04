/**
 * OAuth Store Unit Tests
 *
 * Tests for secure in-memory OAuth state management.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useOAuthStore } from './oauthStore'

describe('oauthStore', () => {
  beforeEach(() => {
    // Reset store state before each test
    useOAuthStore.setState({
      state: null,
      codeVerifier: null,
      provider: null,
      createdAt: null,
    })
    // Reset timers
    vi.useRealTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('setOAuthParams', () => {
    it('should store OAuth parameters for Cognito flow', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'test-state-123',
        codeVerifier: 'test-code-verifier-456',
        provider: 'cognito',
      })

      const updatedStore = useOAuthStore.getState()
      expect(updatedStore.state).toBe('test-state-123')
      expect(updatedStore.codeVerifier).toBe('test-code-verifier-456')
      expect(updatedStore.provider).toBe('cognito')
      expect(updatedStore.createdAt).toBeGreaterThan(0)
    })

    it('should store OAuth parameters for GitHub flow (no codeVerifier)', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'github-state-789',
        provider: 'github',
      })

      const updatedStore = useOAuthStore.getState()
      expect(updatedStore.state).toBe('github-state-789')
      expect(updatedStore.codeVerifier).toBeNull()
      expect(updatedStore.provider).toBe('github')
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

      const updatedStore = useOAuthStore.getState()
      expect(updatedStore.state).toBe('second-state')
      expect(updatedStore.codeVerifier).toBe('second-verifier')
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

      // Verify params are cleared
      const clearedStore = useOAuthStore.getState()
      expect(clearedStore.state).toBeNull()
      expect(clearedStore.codeVerifier).toBeNull()
      expect(clearedStore.provider).toBeNull()
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

      const clearedStore = useOAuthStore.getState()
      expect(clearedStore.state).toBeNull()
      expect(clearedStore.codeVerifier).toBeNull()
      expect(clearedStore.provider).toBeNull()
      expect(clearedStore.createdAt).toBeNull()
    })
  })

  describe('isExpired', () => {
    it('should return true when no params are set', () => {
      const store = useOAuthStore.getState()
      expect(store.isExpired()).toBe(true)
    })

    it('should return false for recently set params', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'fresh-state',
        provider: 'github',
      })

      expect(useOAuthStore.getState().isExpired()).toBe(false)
    })

    it('should return true after 5 minutes', () => {
      vi.useFakeTimers()

      const store = useOAuthStore.getState()
      store.setOAuthParams({
        state: 'old-state',
        provider: 'github',
      })

      // Fast-forward 6 minutes
      vi.advanceTimersByTime(6 * 60 * 1000)

      expect(useOAuthStore.getState().isExpired()).toBe(true)
    })

    it('should return false just before 5 minutes', () => {
      vi.useFakeTimers()

      const store = useOAuthStore.getState()
      store.setOAuthParams({
        state: 'valid-state',
        provider: 'cognito',
      })

      // Fast-forward 4 minutes 59 seconds
      vi.advanceTimersByTime(4 * 60 * 1000 + 59 * 1000)

      expect(useOAuthStore.getState().isExpired()).toBe(false)
    })
  })

  describe('getAndClearParams with expiry', () => {
    it('should return nulls for expired params', () => {
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
  })

  describe('security properties', () => {
    it('should not persist to localStorage', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'secret-state',
        codeVerifier: 'secret-verifier',
        provider: 'cognito',
      })

      // Check that nothing was written to localStorage
      expect(localStorage.getItem('oauth_state')).toBeNull()
      expect(localStorage.getItem('oauth_code_verifier')).toBeNull()
      expect(localStorage.getItem('oauth_provider')).toBeNull()
    })

    it('should not persist to sessionStorage', () => {
      const store = useOAuthStore.getState()

      store.setOAuthParams({
        state: 'secret-state',
        codeVerifier: 'secret-verifier',
        provider: 'cognito',
      })

      // Check that nothing was written to sessionStorage
      expect(sessionStorage.getItem('oauth_state')).toBeNull()
      expect(sessionStorage.getItem('oauth_code_verifier')).toBeNull()
      expect(sessionStorage.getItem('oauth_provider')).toBeNull()
    })
  })
})
