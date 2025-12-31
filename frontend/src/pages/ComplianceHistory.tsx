/**
 * Compliance History Dashboard Page.
 *
 * Displays historical compliance trends, state changes,
 * and alerts for the selected cloud account.
 */

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { History, ArrowLeft } from 'lucide-react'
import { Link } from 'react-router-dom'
import { evaluationHistoryApi } from '../services/api'
import { useSelectedAccount } from '../hooks/useSelectedAccount'
import {
  ComplianceTrendChart,
  ComplianceAlertsList,
  AccountComplianceSummary,
} from '../components/evaluation-history'

export default function ComplianceHistory() {
  const { selectedAccount, isLoading: accountsLoading, hasAccounts } = useSelectedAccount()
  const [trendDays, setTrendDays] = useState(30)

  // Calculate date range for queries - memoized to prevent infinite refetch loop
  // Without useMemo, new Date strings are created every render, changing the queryKey
  const { startDate, endDate } = useMemo(() => {
    const end = new Date()
    const start = new Date(end.getTime() - trendDays * 24 * 60 * 60 * 1000)
    return {
      startDate: start.toISOString(),
      endDate: end.toISOString(),
    }
  }, [trendDays])

  // Fetch account summary
  const { data: summaryData, isLoading: summaryLoading, error: summaryError } = useQuery({
    queryKey: ['evaluation-summary', selectedAccount?.id, startDate, endDate],
    queryFn: () =>
      evaluationHistoryApi.getAccountSummary(selectedAccount!.id, {
        start_date: startDate,
        end_date: endDate,
      }),
    enabled: !!selectedAccount,
    retry: 1,
  })

  // Fetch trends data
  const { data: trendsData, isLoading: trendsLoading, error: trendsError } = useQuery({
    queryKey: ['evaluation-trends', selectedAccount?.id, startDate, endDate],
    queryFn: () =>
      evaluationHistoryApi.getAccountTrends(selectedAccount!.id, {
        start_date: startDate,
        end_date: endDate,
      }),
    enabled: !!selectedAccount,
    retry: 1,
  })

  // Fetch alerts
  const { data: alertsData, isLoading: alertsLoading, error: alertsError } = useQuery({
    queryKey: ['evaluation-alerts', selectedAccount?.id],
    queryFn: () =>
      evaluationHistoryApi.getAccountAlerts(selectedAccount!.id, {
        limit: 50,
      }),
    enabled: !!selectedAccount,
    retry: 1,
  })

  // Check if all queries have errors
  const hasErrors = summaryError || trendsError || alertsError

  // No accounts state
  if (!accountsLoading && !hasAccounts) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh]">
        <History className="h-16 w-16 text-gray-600 mb-4" />
        <h2 className="text-xl font-semibold text-white mb-2">No Cloud Accounts</h2>
        <p className="text-gray-400 mb-4">Connect a cloud account to view compliance history.</p>
        <Link
          to="/accounts"
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          Connect Account
        </Link>
      </div>
    )
  }

  // Loading state
  if (accountsLoading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  // Error state
  if (hasErrors && !summaryLoading && !trendsLoading && !alertsLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh]">
        <History className="h-16 w-16 text-gray-600 mb-4" />
        <h2 className="text-xl font-semibold text-white mb-2">No History Data Available</h2>
        <p className="text-gray-400 mb-4 text-center max-w-md">
          Compliance history data is generated after scans are completed.
          Run a scan to start tracking your detection health over time.
        </p>
        <Link
          to="/compliance"
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Compliance
        </Link>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Link
            to="/dashboard"
            className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
          >
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Compliance History</h1>
            <p className="text-gray-400">
              Track detection health and compliance changes over time
              {selectedAccount && (
                <span className="text-gray-500"> for {selectedAccount.name}</span>
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Summary and Trend Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <AccountComplianceSummary data={summaryData || null} isLoading={summaryLoading} />
        <ComplianceTrendChart
          data={trendsData?.data_points || []}
          isLoading={trendsLoading}
          comparison={trendsData?.comparison}
          onPeriodChange={setTrendDays}
        />
      </div>

      {/* Alerts Section */}
      <div className="mb-6">
        <ComplianceAlertsList
          alerts={alertsData?.alerts || []}
          isLoading={alertsLoading}
          summary={alertsData?.summary}
          accountId={selectedAccount?.id}
        />
      </div>

      {/* Organisation Overview (if viewing org-level) */}
      {!selectedAccount && (
        <OrgOverview />
      )}
    </div>
  )
}

/**
 * Organisation-level overview component.
 */
function OrgOverview() {
  const { data: orgData, isLoading } = useQuery({
    queryKey: ['evaluation-org-summary'],
    queryFn: () => evaluationHistoryApi.getOrgSummary({}),
  })

  if (isLoading) {
    return (
      <div className="card p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-700 rounded w-48 mb-4" />
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 bg-gray-700/50 rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (!orgData) {
    return null
  }

  return (
    <div className="card p-6">
      <h3 className="text-lg font-semibold text-white mb-4">Organisation Overview</h3>

      {/* Summary Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-700/50 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-white">{orgData.summary.total_accounts}</p>
          <p className="text-xs text-gray-400">Accounts</p>
        </div>
        <div className="bg-gray-700/50 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-white">{orgData.summary.total_detections}</p>
          <p className="text-xs text-gray-400">Detections</p>
        </div>
        <div className="bg-gray-700/50 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-green-400">
            {orgData.summary.overall_health_percentage.toFixed(1)}%
          </p>
          <p className="text-xs text-gray-400">Health</p>
        </div>
        <div className="bg-gray-700/50 rounded-lg p-4 text-center">
          <p className="text-2xl font-bold text-yellow-400">{orgData.summary.total_alerts}</p>
          <p className="text-xs text-gray-400">Alerts</p>
        </div>
      </div>

      {/* Accounts Needing Attention */}
      {orgData.accounts_needing_attention.length > 0 && (
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-400 mb-3">Accounts Needing Attention</h4>
          <div className="space-y-2">
            {orgData.accounts_needing_attention.map((account) => (
              <div
                key={account.cloud_account_id}
                className="flex items-center justify-between bg-red-900/20 border border-red-900/50 rounded-lg p-3"
              >
                <div>
                  <p className="text-white font-medium">{account.account_name}</p>
                  <p className="text-xs text-gray-400">{account.reason.replace(/_/g, ' ')}</p>
                </div>
                <div className="text-right">
                  {account.health_percentage !== null && (
                    <p className="text-red-400 font-medium">
                      {account.health_percentage.toFixed(1)}% health
                    </p>
                  )}
                  {account.critical_alerts > 0 && (
                    <p className="text-xs text-red-400">{account.critical_alerts} alerts</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Accounts */}
      <div>
        <h4 className="text-sm font-medium text-gray-400 mb-3">All Accounts</h4>
        <div className="space-y-2">
          {orgData.by_account.map((account) => (
            <div
              key={account.cloud_account_id}
              className="flex items-center justify-between bg-gray-700/30 rounded-lg p-3 hover:bg-gray-700/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500 uppercase">{account.provider}</span>
                <p className="text-white">{account.account_name}</p>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-sm text-gray-400">
                  {account.total_detections} detections
                </span>
                <span
                  className={`text-sm font-medium ${
                    account.health_percentage >= 80
                      ? 'text-green-400'
                      : account.health_percentage >= 60
                      ? 'text-yellow-400'
                      : 'text-red-400'
                  }`}
                >
                  {account.health_percentage.toFixed(1)}%
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
