/**
 * AccountSelector - Global Cloud Account Selector Component
 *
 * Displays a dropdown in the navigation sidebar for selecting the active cloud account.
 * Shows provider icon (AWS orange, GCP blue) and account name.
 */

import { useState, useRef, useEffect } from 'react'
import { Cloud, ChevronDown, Check } from 'lucide-react'
import clsx from 'clsx'
import { useSelectedAccount } from '../hooks/useSelectedAccount'
import { CloudAccount } from '../services/api'

// Provider icon colours
const providerStyles = {
  aws: {
    iconColour: 'text-orange-500',
    bgColour: 'bg-orange-500/10',
    label: 'AWS',
  },
  gcp: {
    iconColour: 'text-blue-500',
    bgColour: 'bg-blue-500/10',
    label: 'GCP',
  },
}

export function AccountSelector() {
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  const { selectedAccount, accounts, isLoading, switchAccount, hasAccounts } =
    useSelectedAccount()

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Handle account selection
  const handleSelect = (account: CloudAccount) => {
    switchAccount(account.id)
    setIsOpen(false)
  }

  if (isLoading) {
    return (
      <div className="flex items-center px-3 py-2 text-slate-400">
        <div className="animate-spin h-4 w-4 border-2 border-slate-400 border-t-transparent rounded-full mr-2" />
        <span className="text-sm">Loading...</span>
      </div>
    )
  }

  if (!hasAccounts) {
    return null // Don't show selector if no accounts
  }

  const providerStyle = selectedAccount
    ? providerStyles[selectedAccount.provider]
    : providerStyles.aws

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={clsx(
          'w-full flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colours',
          'bg-slate-800 hover:bg-slate-700 text-slate-200'
        )}
      >
        <div
          className={clsx(
            'flex items-center justify-center w-6 h-6 rounded mr-2',
            providerStyle.bgColour
          )}
        >
          <Cloud className={clsx('h-4 w-4', providerStyle.iconColour)} />
        </div>
        <span className="flex-1 text-left truncate">
          {selectedAccount?.name ?? 'Select Account'}
        </span>
        <ChevronDown
          className={clsx(
            'h-4 w-4 ml-2 transition-transform text-slate-400',
            isOpen && 'rotate-180'
          )}
        />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute top-full left-0 right-0 mt-1 bg-slate-800 rounded-lg shadow-lg border border-slate-700 py-1 z-50">
          <div className="px-3 py-2 border-b border-slate-700">
            <p className="text-xs text-slate-400 uppercase tracking-wider">
              Cloud Accounts
            </p>
          </div>
          <div className="max-h-64 overflow-y-auto">
            {accounts.map((account) => {
              const style = providerStyles[account.provider]
              const isSelected = account.id === selectedAccount?.id

              return (
                <button
                  key={account.id}
                  onClick={() => handleSelect(account)}
                  className={clsx(
                    'w-full flex items-center px-3 py-2 text-left transition-colours',
                    isSelected
                      ? 'bg-slate-700 text-white'
                      : 'text-slate-300 hover:bg-slate-700/50'
                  )}
                >
                  <div
                    className={clsx(
                      'flex items-center justify-center w-6 h-6 rounded mr-3',
                      style.bgColour
                    )}
                  >
                    <Cloud className={clsx('h-4 w-4', style.iconColour)} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {account.name}
                    </p>
                    <p className="text-xs text-slate-500">
                      {style.label} &middot; {account.account_id}
                    </p>
                  </div>
                  {isSelected && (
                    <Check className="h-4 w-4 text-blue-400 ml-2 flex-shrink-0" />
                  )}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

export default AccountSelector
