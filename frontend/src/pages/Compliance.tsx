/**
 * Compliance Coverage Page.
 *
 * Displays compliance framework coverage (CIS Controls, NIST 800-53).
 * URL params preserve modal state for proper back navigation.
 */

import { useSearchParams } from 'react-router-dom'
import { BarChart3 } from 'lucide-react'
import { ComplianceCoverageContent } from '../components/compliance'
import { useSelectedAccount } from '../hooks/useSelectedAccount'

export default function Compliance() {
  const [searchParams] = useSearchParams()
  const { selectedAccount, isLoading: accountsLoading } = useSelectedAccount()

  // Read modal state from URL params (for back navigation restoration)
  const initialModalState = {
    modalType: searchParams.get('modal') as 'covered' | 'partial' | 'uncovered' | 'not_assessable' | null,
    frameworkId: searchParams.get('framework'),
    controlId: searchParams.get('control'),
  }

  if (accountsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!selectedAccount) {
    return (
      <div className="text-center py-12 card">
        <BarChart3 className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-white">No cloud accounts</h3>
        <p className="mt-1 text-sm text-gray-400">
          Add a cloud account to view compliance coverage.
        </p>
      </div>
    )
  }

  return (
    <div className="bg-gray-900 -mx-6 -mb-6 px-6 py-6 rounded-b-lg min-h-[600px]">
      <ComplianceCoverageContent
        accountId={selectedAccount.id}
        initialModalState={initialModalState}
      />
    </div>
  )
}
