/**
 * Reports Page
 *
 * Allows users to generate and download coverage reports in various formats.
 * Free tier users receive watermarked PDF reports.
 */

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  FileText,
  Download,
  FileSpreadsheet,
  Loader2,
  AlertTriangle,
  Info,
  Cloud,
  FileBarChart,
  Check,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { billingApi, Subscription } from '../services/billingApi'
import { reportsApi, downloadReport } from '../services/reportsApi'

interface CloudAccount {
  id: string
  name: string
  provider: string
  account_id: string
  region: string
  status: string
}

// API base URL for cloud accounts
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

export default function Reports() {
  const { accessToken } = useAuth()
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null)
  const [downloading, setDownloading] = useState<string | null>(null)
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Fetch subscription to check tier for watermark notice
  const { data: subscription } = useQuery<Subscription>({
    queryKey: ['subscription'],
    queryFn: () => billingApi.getSubscription(accessToken!),
    enabled: !!accessToken,
  })

  // Fetch cloud accounts
  const { data: accounts, isLoading: accountsLoading } = useQuery<CloudAccount[]>({
    queryKey: ['cloud-accounts'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE_URL}/api/v1/cloud-accounts`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      if (!response.ok) throw new Error('Failed to fetch accounts')
      return response.json()
    },
    enabled: !!accessToken,
  })

  const isFreeUser = subscription?.tier === 'free_scan'
  const selectedAccount = accounts?.find((a) => a.id === selectedAccountId)

  const handleDownload = async (
    reportType: 'coverage' | 'gaps' | 'detections' | 'executive' | 'full'
  ) => {
    if (!accessToken || !selectedAccountId) return

    setDownloading(reportType)
    setError(null)
    setDownloadSuccess(null)

    try {
      let result

      switch (reportType) {
        case 'coverage':
          result = await reportsApi.downloadCoverageCsv(accessToken, selectedAccountId)
          break
        case 'gaps':
          result = await reportsApi.downloadGapsCsv(accessToken, selectedAccountId)
          break
        case 'detections':
          result = await reportsApi.downloadDetectionsCsv(accessToken, selectedAccountId)
          break
        case 'executive':
          result = await reportsApi.downloadExecutivePdf(accessToken, selectedAccountId, {
            includeGaps: true,
            includeDetections: false,
          })
          break
        case 'full':
          result = await reportsApi.downloadFullPdf(accessToken, selectedAccountId)
          break
      }

      downloadReport(result)
      setDownloadSuccess(reportType)

      // Clear success after 3 seconds
      setTimeout(() => setDownloadSuccess(null), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to download report')
    } finally {
      setDownloading(null)
    }
  }

  const reportTypes = [
    {
      id: 'coverage' as const,
      name: 'Coverage Report',
      description: 'Full MITRE ATT&CK technique coverage breakdown with status and confidence scores',
      format: 'CSV',
      icon: FileSpreadsheet,
      colour: 'text-green-600 bg-green-100',
    },
    {
      id: 'gaps' as const,
      name: 'Gap Analysis Report',
      description: 'Priority-ranked coverage gaps with recommended actions',
      format: 'CSV',
      icon: FileSpreadsheet,
      colour: 'text-orange-600 bg-orange-100',
    },
    {
      id: 'detections' as const,
      name: 'Detection Inventory',
      description: 'Complete list of discovered detections with metadata and mapping status',
      format: 'CSV',
      icon: FileSpreadsheet,
      colour: 'text-blue-600 bg-blue-100',
    },
    {
      id: 'executive' as const,
      name: 'Executive Summary',
      description: 'High-level overview with key metrics, tactic coverage, and top gaps',
      format: 'PDF',
      icon: FileText,
      colour: 'text-purple-600 bg-purple-100',
      isPdf: true,
    },
    {
      id: 'full' as const,
      name: 'Full Report',
      description: 'Comprehensive report including executive summary, gap analysis, and detection details',
      format: 'PDF',
      icon: FileBarChart,
      colour: 'text-indigo-600 bg-indigo-100',
      isPdf: true,
    },
  ]

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-gray-600">
          Generate and download detection coverage reports
        </p>
      </div>

      {/* Free tier watermark notice */}
      {isFreeUser && (
        <div className="mb-6 p-4 bg-amber-50 border border-amber-200 rounded-lg flex items-start">
          <Info className="h-5 w-5 text-amber-600 mr-3 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-medium text-amber-900">Free Tier Notice</h3>
            <p className="text-sm text-amber-800 mt-1">
              PDF reports on the free tier include a watermark. Upgrade to Subscriber or
              Enterprise to receive unwatermarked reports.
            </p>
          </div>
        </div>
      )}

      {/* Account Selection */}
      <div className="card mb-6">
        <h2 className="text-lg font-semibold mb-4">Select Cloud Account</h2>

        {accountsLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
          </div>
        ) : !accounts?.length ? (
          <div className="text-center py-8 text-gray-500">
            <Cloud className="h-12 w-12 mx-auto mb-3 text-gray-400" />
            <p>No cloud accounts found</p>
            <p className="text-sm mt-1">Connect a cloud account to generate reports</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {accounts.map((account) => (
              <button
                key={account.id}
                onClick={() => setSelectedAccountId(account.id)}
                className={`p-4 border rounded-lg text-left transition-all ${
                  selectedAccountId === account.id
                    ? 'border-blue-500 bg-blue-50 ring-2 ring-blue-200'
                    : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <Cloud
                      className={`h-5 w-5 mr-2 ${
                        account.provider === 'aws'
                          ? 'text-orange-500'
                          : 'text-blue-500'
                      }`}
                    />
                    <span className="font-medium">{account.name}</span>
                  </div>
                  {selectedAccountId === account.id && (
                    <Check className="h-5 w-5 text-blue-600" />
                  )}
                </div>
                <div className="text-sm text-gray-500 mt-2">
                  <span className="uppercase">{account.provider}</span>
                  <span className="mx-2">&middot;</span>
                  <span className="font-mono">{account.account_id}</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Error message */}
      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center text-red-800">
          <AlertTriangle className="h-5 w-5 mr-2" />
          {error}
        </div>
      )}

      {/* Report Types */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Available Reports</h2>

        {!selectedAccountId ? (
          <div className="text-center py-8 text-gray-500">
            <FileText className="h-12 w-12 mx-auto mb-3 text-gray-400" />
            <p>Select a cloud account to view available reports</p>
          </div>
        ) : (
          <div className="space-y-4">
            {reportTypes.map((report) => (
              <div
                key={report.id}
                className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50"
              >
                <div className="flex items-start">
                  <div className={`p-2 rounded-lg ${report.colour}`}>
                    <report.icon className="h-5 w-5" />
                  </div>
                  <div className="ml-4">
                    <div className="flex items-center">
                      <h3 className="font-medium text-gray-900">{report.name}</h3>
                      <span className="ml-2 px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 text-gray-600">
                        {report.format}
                      </span>
                      {report.isPdf && isFreeUser && (
                        <span className="ml-2 px-2 py-0.5 text-xs font-medium rounded-full bg-amber-100 text-amber-700">
                          Watermarked
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-500 mt-1">{report.description}</p>
                  </div>
                </div>

                <button
                  onClick={() => handleDownload(report.id)}
                  disabled={downloading === report.id}
                  className={`flex items-center px-4 py-2 rounded-lg font-medium transition-colors ${
                    downloadSuccess === report.id
                      ? 'bg-green-100 text-green-700'
                      : 'bg-blue-600 text-white hover:bg-blue-700'
                  } disabled:opacity-50 disabled:cursor-not-allowed`}
                >
                  {downloading === report.id ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Generating...
                    </>
                  ) : downloadSuccess === report.id ? (
                    <>
                      <Check className="h-4 w-4 mr-2" />
                      Downloaded
                    </>
                  ) : (
                    <>
                      <Download className="h-4 w-4 mr-2" />
                      Download
                    </>
                  )}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Selected account info */}
      {selectedAccount && (
        <div className="mt-6 text-sm text-gray-500">
          Generating reports for:{' '}
          <span className="font-medium text-gray-900">{selectedAccount.name}</span>
          <span className="mx-2">&middot;</span>
          <span className="font-mono">{selectedAccount.account_id}</span>
        </div>
      )}
    </div>
  )
}
