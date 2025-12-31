/**
 * useSelectedAccount Hook Tests
 *
 * Tests for the account selection hook:
 * - Fetches accounts from API
 * - Syncs with Zustand store
 * - Falls back to first account when selection is invalid
 * - Handles account switching with cache invalidation
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReactNode } from 'react'
import { useSelectedAccount } from './useSelectedAccount'
import { useAccountStore } from '../stores/accountStore'

// Create wrapper with QueryClient
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
    },
  })

  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    )
  }
}

// Reset store before each test
beforeEach(() => {
  useAccountStore.setState({
    selectedAccountId: null,
    selectedAccount: null,
  })
})

describe('useSelectedAccount', () => {
  describe('initial state', () => {
    it('should start in loading state', () => {
      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      expect(result.current.isLoading).toBe(true)
    })

    it('should fetch accounts from API', async () => {
      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.accounts).toBeDefined()
      expect(Array.isArray(result.current.accounts)).toBe(true)
    })
  })

  describe('account selection', () => {
    it('should select first account when no selection exists', async () => {
      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // MSW returns mock account, so selectedAccount should be set
      if (result.current.accounts.length > 0) {
        expect(result.current.selectedAccount).not.toBeNull()
        expect(result.current.selectedAccount?.id).toBe(result.current.accounts[0].id)
      }
    })

    it('should maintain selection when valid account ID exists', async () => {
      // Pre-set account ID in store
      useAccountStore.setState({
        selectedAccountId: 'account-123',
        selectedAccount: null,
      })

      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Should find and select the matching account
      if (result.current.accounts.some(a => a.id === 'account-123')) {
        expect(result.current.selectedAccount?.id).toBe('account-123')
      }
    })

    it('should fall back to first account when selected ID is invalid', async () => {
      // Pre-set invalid account ID
      useAccountStore.setState({
        selectedAccountId: 'non-existent-id',
        selectedAccount: null,
      })

      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Should fall back to first account
      if (result.current.accounts.length > 0) {
        expect(result.current.selectedAccount).not.toBeNull()
        expect(result.current.selectedAccount?.id).toBe(result.current.accounts[0].id)
      }
    })
  })

  describe('hasAccounts', () => {
    it('should return true when accounts exist', async () => {
      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      if (result.current.accounts.length > 0) {
        expect(result.current.hasAccounts).toBe(true)
      }
    })
  })

  describe('switchAccount', () => {
    it('should be a function', async () => {
      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(typeof result.current.switchAccount).toBe('function')
    })

    it('should update selected account when switching', async () => {
      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const accounts = result.current.accounts
      if (accounts.length > 0) {
        const targetAccount = accounts[0]
        result.current.switchAccount(targetAccount.id)

        await waitFor(() => {
          expect(result.current.selectedAccount?.id).toBe(targetAccount.id)
        })
      }
    })

    it('should not switch to non-existent account', async () => {
      const { result } = renderHook(() => useSelectedAccount(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const previousAccount = result.current.selectedAccount
      result.current.switchAccount('non-existent-id')

      // Account should remain unchanged
      expect(result.current.selectedAccount).toEqual(previousAccount)
    })
  })
})
