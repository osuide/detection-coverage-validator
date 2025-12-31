/**
 * Account Store Tests
 *
 * Tests for the Zustand account store, including:
 * - Account selection state management
 * - Account clearing
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { useAccountStore, SelectedAccount } from './accountStore'

// Reset store before each test using the store's own clear action
beforeEach(() => {
  // Get the store and use the clearSelectedAccount action
  const store = useAccountStore.getState()
  if (store.clearSelectedAccount) {
    store.clearSelectedAccount()
  }
})

describe('useAccountStore', () => {
  const mockAccount: SelectedAccount = {
    id: 'account-123',
    name: 'Production AWS',
    provider: 'aws',
    account_id: '123456789012',
  }

  const mockGcpAccount: SelectedAccount = {
    id: 'account-456',
    name: 'Production GCP',
    provider: 'gcp',
    account_id: 'my-gcp-project',
  }

  describe('initial state', () => {
    it('should have null values initially', () => {
      const state = useAccountStore.getState()

      expect(state.selectedAccountId).toBeNull()
      expect(state.selectedAccount).toBeNull()
    })
  })

  describe('setSelectedAccount', () => {
    it('should set account and account ID', () => {
      useAccountStore.getState().setSelectedAccount(mockAccount)

      const state = useAccountStore.getState()

      expect(state.selectedAccount).toEqual(mockAccount)
      expect(state.selectedAccountId).toBe('account-123')
    })

    it('should handle AWS accounts', () => {
      useAccountStore.getState().setSelectedAccount(mockAccount)

      const state = useAccountStore.getState()

      expect(state.selectedAccount?.provider).toBe('aws')
      expect(state.selectedAccount?.account_id).toBe('123456789012')
    })

    it('should handle GCP accounts', () => {
      useAccountStore.getState().setSelectedAccount(mockGcpAccount)

      const state = useAccountStore.getState()

      expect(state.selectedAccount?.provider).toBe('gcp')
      expect(state.selectedAccount?.account_id).toBe('my-gcp-project')
    })

    it('should clear account when passed null', () => {
      // First set an account
      useAccountStore.getState().setSelectedAccount(mockAccount)
      expect(useAccountStore.getState().selectedAccount).not.toBeNull()

      // Then clear it
      useAccountStore.getState().setSelectedAccount(null)

      const state = useAccountStore.getState()

      expect(state.selectedAccount).toBeNull()
      expect(state.selectedAccountId).toBeNull()
    })
  })

  describe('setSelectedAccountId', () => {
    it('should set only the account ID', () => {
      useAccountStore.getState().setSelectedAccountId('account-789')

      const state = useAccountStore.getState()

      expect(state.selectedAccountId).toBe('account-789')
      // Note: Full account object would be synced by hook in real usage
    })

    it('should clear ID when passed null', () => {
      useAccountStore.getState().setSelectedAccountId('account-789')
      useAccountStore.getState().setSelectedAccountId(null)

      expect(useAccountStore.getState().selectedAccountId).toBeNull()
    })
  })

  describe('clearSelectedAccount', () => {
    it('should clear both account and account ID', () => {
      // First set an account
      useAccountStore.getState().setSelectedAccount(mockAccount)
      expect(useAccountStore.getState().selectedAccount).not.toBeNull()
      expect(useAccountStore.getState().selectedAccountId).not.toBeNull()

      // Then clear
      useAccountStore.getState().clearSelectedAccount()

      const state = useAccountStore.getState()

      expect(state.selectedAccount).toBeNull()
      expect(state.selectedAccountId).toBeNull()
    })
  })

  describe('switching accounts', () => {
    it('should allow switching between accounts', () => {
      // Select first account
      useAccountStore.getState().setSelectedAccount(mockAccount)
      expect(useAccountStore.getState().selectedAccountId).toBe('account-123')

      // Switch to second account
      useAccountStore.getState().setSelectedAccount(mockGcpAccount)

      const state = useAccountStore.getState()

      expect(state.selectedAccountId).toBe('account-456')
      expect(state.selectedAccount?.provider).toBe('gcp')
    })
  })
})
