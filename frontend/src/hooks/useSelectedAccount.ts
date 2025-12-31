/**
 * useSelectedAccount - Global Account Selection Hook
 *
 * This hook:
 * - Fetches available accounts via React Query
 * - Syncs selected account with available accounts
 * - Falls back to first account if selection is invalid
 * - Provides account switching with cache invalidation
 */

import { useEffect, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { accountsApi, CloudAccount } from '../services/api'
import { useAccountStore } from '../stores/accountStore'

interface UseSelectedAccountReturn {
  // Selected account (null if no accounts exist)
  selectedAccount: CloudAccount | null

  // All available accounts
  accounts: CloudAccount[]

  // Loading state
  isLoading: boolean

  // Switch to a different account
  switchAccount: (accountId: string) => void

  // Check if there are accounts available
  hasAccounts: boolean
}

export function useSelectedAccount(): UseSelectedAccountReturn {
  const queryClient = useQueryClient()

  const { selectedAccountId, setSelectedAccount, setSelectedAccountId } =
    useAccountStore()

  // Fetch accounts
  const { data: accounts = [], isLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn: accountsApi.list,
  })

  // Sync selected account with available accounts
  useEffect(() => {
    if (isLoading) {
      return
    }

    // If no accounts exist, clear any stale selection from localStorage
    if (accounts.length === 0) {
      if (selectedAccountId) {
        setSelectedAccountId(null)
        setSelectedAccount(null)
      }
      return
    }

    // Find the selected account in the list
    let targetAccount: CloudAccount | null = null

    if (selectedAccountId) {
      targetAccount = accounts.find((a) => a.id === selectedAccountId) ?? null
    }

    // Fall back to first account if selection is invalid
    if (!targetAccount && accounts.length > 0) {
      targetAccount = accounts[0]
    }

    if (targetAccount) {
      setSelectedAccount({
        id: targetAccount.id,
        name: targetAccount.name,
        provider: targetAccount.provider,
        account_id: targetAccount.account_id,
      })
    }
  }, [accounts, selectedAccountId, isLoading, setSelectedAccount, setSelectedAccountId])

  // Switch account with cache invalidation
  const switchAccount = useCallback(
    (accountId: string) => {
      const account = accounts.find((a) => a.id === accountId)
      if (!account) return

      // Update store
      setSelectedAccountId(accountId)

      // Invalidate account-specific queries to force refetch
      queryClient.invalidateQueries({ queryKey: ['coverage'] })
      queryClient.invalidateQueries({ queryKey: ['techniques'] })
      queryClient.invalidateQueries({ queryKey: ['detections'] })
      queryClient.invalidateQueries({ queryKey: ['acknowledgedGaps'] })
      queryClient.invalidateQueries({ queryKey: ['compliance-summary'] })
      queryClient.invalidateQueries({ queryKey: ['compliance-coverage'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    [accounts, setSelectedAccountId, queryClient]
  )

  // Get full account object
  const selectedAccount =
    accounts.find((a) => a.id === selectedAccountId) ??
    (accounts.length > 0 ? accounts[0] : null)

  return {
    selectedAccount,
    accounts,
    isLoading,
    switchAccount,
    hasAccounts: accounts.length > 0,
  }
}

export default useSelectedAccount
