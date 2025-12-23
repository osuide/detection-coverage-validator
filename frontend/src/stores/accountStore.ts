/**
 * Zustand Cloud Account Store - Global Account Selection
 *
 * This store manages the selected cloud account globally:
 * - Persists selection to localStorage
 * - Syncs with available accounts from React Query
 * - Provides actions to switch accounts
 */

import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

export interface SelectedAccount {
  id: string
  name: string
  provider: 'aws' | 'gcp'
  account_id: string
}

interface AccountState {
  // State
  selectedAccountId: string | null
  selectedAccount: SelectedAccount | null

  // Actions
  setSelectedAccount: (account: SelectedAccount | null) => void
  setSelectedAccountId: (id: string | null) => void
  clearSelectedAccount: () => void
}

export const useAccountStore = create<AccountState>()(
  persist(
    (set) => ({
      selectedAccountId: null,
      selectedAccount: null,

      setSelectedAccount: (account) =>
        set({
          selectedAccount: account,
          selectedAccountId: account?.id ?? null,
        }),

      setSelectedAccountId: (id) =>
        set({
          selectedAccountId: id,
          // Note: Full account object will be synced by the useSelectedAccount hook
        }),

      clearSelectedAccount: () =>
        set({
          selectedAccount: null,
          selectedAccountId: null,
        }),
    }),
    {
      name: 'dcv-selected-account',
      storage: createJSONStorage(() => localStorage),
      // Only persist the account ID, not the full object
      partialize: (state) => ({
        selectedAccountId: state.selectedAccountId,
      }),
    }
  )
)

export default useAccountStore
