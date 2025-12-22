/**
 * Compliance Coverage Page.
 *
 * Displays compliance framework coverage (CIS Controls, NIST 800-53).
 * URL params preserve modal state for proper back navigation.
 */

import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { BarChart3 } from 'lucide-react'
import { accountsApi } from '../services/api'
import { ComplianceCoverageContent } from '../components/compliance'

export default function Compliance() {
  const [searchParams] = useSearchParams()

  const { data: accounts, isLoading: accountsLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn: accountsApi.list,
  })

  const firstAccount = accounts?.[0]

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

  if (!firstAccount) {
    return (
      <div className="text-center py-12 card">
        <BarChart3 className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-gray-900">No cloud accounts</h3>
        <p className="mt-1 text-sm text-gray-500">
          Add a cloud account to view compliance coverage.
        </p>
      </div>
    )
  }

  return (
    <div className="bg-gray-900 -mx-6 -mb-6 px-6 py-6 rounded-b-lg min-h-[600px]">
      <ComplianceCoverageContent
        accountId={firstAccount.id}
        initialModalState={initialModalState}
      />
    </div>
  )
}
