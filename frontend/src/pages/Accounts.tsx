import { useState, useEffect, useCallback, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Cloud, Plus, Trash2, Play, RefreshCw, Link, CheckCircle2, AlertTriangle, Settings, Clock, Globe, MapPin, Calendar } from 'lucide-react'
import { Link as RouterLink } from 'react-router'
import { accountsApi, scansApi, credentialsApi, CloudAccount, scanStatusApi, ScanStatus, RegionConfig, Scan } from '../services/api'
import CredentialWizard from '../components/CredentialWizard'
import RegionSelector from '../components/RegionSelector'
import ScheduleModal, { ScheduleIndicator } from '../components/ScheduleModal'

export default function Accounts() {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [connectingAccount, setConnectingAccount] = useState<CloudAccount | null>(null)
  const [editingAccount, setEditingAccount] = useState<CloudAccount | null>(null)
  const [schedulingAccount, setSchedulingAccount] = useState<CloudAccount | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    provider: 'aws' as 'aws' | 'gcp' | 'azure',
    account_id: '',
    regions: [] as string[],
    region_config: {
      mode: 'selected',
      regions: ['eu-west-2'],  // A13E's primary region
    } as RegionConfig,
    // Azure-specific fields
    azure_workload_identity_config: undefined as { tenant_id: string; client_id: string; subscription_id: string } | undefined,
    azure_enabled: false,
  })

  const { data: accounts, isLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn: accountsApi.list,
  })

  // Check scan limits
  const { data: scanStatus } = useQuery({
    queryKey: ['scanStatus'],
    queryFn: scanStatusApi.get,
  })

  const createMutation = useMutation({
    mutationFn: accountsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['accounts'] })
      setShowForm(false)
      setFormData({
        name: '',
        provider: 'aws' as 'aws' | 'gcp' | 'azure',
        account_id: '',
        regions: [],
        region_config: { mode: 'selected', regions: ['eu-west-2'] },
        azure_workload_identity_config: undefined,
        azure_enabled: false,
      })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CloudAccount> }) =>
      accountsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['accounts'] })
      setEditingAccount(null)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: accountsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['accounts'] })
    },
  })

  // Track active scans per account: accountId -> scanId
  const [activeScans, setActiveScans] = useState<Record<string, string>>({})
  // Track scan progress for display: scanId -> Scan object
  const [scanProgress, setScanProgress] = useState<Record<string, Scan>>({})
  // Feedback message for scan status
  const [scanFeedback, setScanFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Track consecutive poll failures per scan (for silent retry on transient errors)
  const pollFailures = useRef<Record<string, number>>({})

  // Helper to detect transient errors (network, 504, etc.) that should be retried silently
  const isTransientError = (error: unknown): boolean => {
    if (!error || typeof error !== 'object') return false
    const err = error as { code?: string; response?: { status?: number } }
    // Network errors (CORS blocked due to 504, connection refused, etc.)
    if (err.code === 'ERR_NETWORK' || err.code === 'ECONNABORTED') return true
    // Gateway timeout (504), bad gateway (502), service unavailable (503)
    const status = err.response?.status
    if (status && status >= 500) return true
    return false
  }

  // Maximum silent retries before showing error
  const MAX_SILENT_RETRIES = 5

  // Poll active scans for completion
  const pollActiveScan = useCallback(async (accountId: string, scanId: string) => {
    try {
      const scan = await scansApi.get(scanId)
      // Reset failure count on success
      pollFailures.current[scanId] = 0
      setScanProgress(prev => ({ ...prev, [scanId]: scan }))

      if (scan.status === 'completed') {
        // Scan completed successfully - clean up tracking
        delete pollFailures.current[scanId]
        setActiveScans(prev => {
          const next = { ...prev }
          delete next[accountId]
          return next
        })
        setScanProgress(prev => {
          const next = { ...prev }
          delete next[scanId]
          return next
        })
        queryClient.invalidateQueries({ queryKey: ['scans'] })
        queryClient.invalidateQueries({ queryKey: ['scanStatus'] })
        queryClient.invalidateQueries({ queryKey: ['coverage'] })
        queryClient.invalidateQueries({ queryKey: ['accounts'] })
        setScanFeedback({
          type: 'success',
          message: `Scan completed! Found ${scan.detections_found} detections.`
        })
        setTimeout(() => setScanFeedback(null), 5000)
      } else if (scan.status === 'failed') {
        // Scan failed - clean up tracking
        delete pollFailures.current[scanId]
        setActiveScans(prev => {
          const next = { ...prev }
          delete next[accountId]
          return next
        })
        setScanProgress(prev => {
          const next = { ...prev }
          delete next[scanId]
          return next
        })
        setScanFeedback({
          type: 'error',
          message: 'Scan failed. Please check your credentials and try again.'
        })
        setTimeout(() => setScanFeedback(null), 5000)
      }
      // If still running/pending, polling continues via useEffect
    } catch (error) {
      // Track consecutive failures
      const failures = (pollFailures.current[scanId] || 0) + 1
      pollFailures.current[scanId] = failures

      // For transient errors (network, 504), silently continue polling
      if (isTransientError(error) && failures < MAX_SILENT_RETRIES) {
        // Silently retry - don't log or show error yet
        return
      }

      // After max retries or for non-transient errors, log and potentially show error
      if (failures >= MAX_SILENT_RETRIES) {
        // Only log after multiple failures to avoid console spam
        console.warn(`Poll failed ${failures} times for scan ${scanId}, continuing...`)
      }
      // Note: We don't stop polling - the scan may still complete
      // The polling will stop naturally when the scan completes or fails on the server side
    }
  }, [queryClient])

  // Effect to poll active scans every 2 seconds
  useEffect(() => {
    const activeScanEntries = Object.entries(activeScans)
    if (activeScanEntries.length === 0) return

    const pollInterval = setInterval(() => {
      activeScanEntries.forEach(([accountId, scanId]) => {
        pollActiveScan(accountId, scanId)
      })
    }, 2000)

    // Initial poll immediately
    activeScanEntries.forEach(([accountId, scanId]) => {
      pollActiveScan(accountId, scanId)
    })

    return () => clearInterval(pollInterval)
  }, [activeScans, pollActiveScan])

  // Use useMutation for scan to prevent double-click race conditions
  const scanMutation = useMutation({
    mutationFn: (accountId: string) => scansApi.create({ cloud_account_id: accountId }),
    onMutate: () => {
      // Clear any previous feedback
      setScanFeedback(null)
    },
    onSuccess: (scan, accountId) => {
      // Store the scan ID to start polling
      setActiveScans(prev => ({ ...prev, [accountId]: scan.id }))
      setScanProgress(prev => ({ ...prev, [scan.id]: scan }))
      // Invalidate scan status to update limits
      queryClient.invalidateQueries({ queryKey: ['scanStatus'] })
    },
    onError: (error: unknown) => {
      const err = error as { message?: string; response?: { data?: { detail?: string } } }
      setScanFeedback({
        type: 'error',
        message: err.response?.data?.detail || err.message || 'Failed to start scan. Please try again.'
      })
      setTimeout(() => setScanFeedback(null), 5000)
    },
  })

  // Wrapper to prevent double-clicks - check both mutation pending and active scans
  const handleScan = (accountId: string) => {
    // Prevent if mutation is pending or if there's already an active scan for this account
    if (!scanMutation.isPending && !activeScans[accountId]) {
      scanMutation.mutate(accountId)
    }
  }

  // Helper to check if an account has an active scan
  const isAccountScanning = (accountId: string) => {
    return !!activeScans[accountId] || (scanMutation.isPending && scanMutation.variables === accountId)
  }

  // Get scan progress for an account
  const getAccountScanProgress = (accountId: string): Scan | null => {
    const scanId = activeScans[accountId]
    return scanId ? scanProgress[scanId] || null : null
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    createMutation.mutate(formData)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Cloud Accounts</h1>
          <p className="text-gray-400">Manage your cloud accounts for scanning</p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="btn-primary flex items-center"
        >
          <Plus className="h-4 w-4 mr-2" />
          Add Account
        </button>
      </div>

      {/* Scan Feedback Message */}
      {scanFeedback && (
        <div
          className={`mb-4 p-4 rounded-lg flex items-center justify-between ${
            scanFeedback.type === 'success'
              ? 'bg-green-900/30 border border-green-700 text-green-400'
              : 'bg-red-900/30 border border-red-700 text-red-400'
          }`}
        >
          <div className="flex items-center">
            {scanFeedback.type === 'success' ? (
              <CheckCircle2 className="h-5 w-5 mr-2" />
            ) : (
              <AlertTriangle className="h-5 w-5 mr-2" />
            )}
            <span>{scanFeedback.message}</span>
          </div>
          <button
            onClick={() => setScanFeedback(null)}
            className="text-gray-400 hover:text-gray-300"
          >
            &times;
          </button>
        </div>
      )}

      {/* Add Account Form */}
      {showForm && (
        <div className="card mb-6">
          <h3 className="text-lg font-semibold mb-4">Add Cloud Account</h3>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Account Name
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder={formData.provider === 'gcp' ? 'My GCP Project' : formData.provider === 'azure' ? 'My Azure Subscription' : 'My AWS Account'}
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Provider
                </label>
                <select
                  value={formData.provider}
                  onChange={(e) => {
                    const newProvider = e.target.value as 'aws' | 'gcp' | 'azure'
                    setFormData({
                      ...formData,
                      provider: newProvider,
                      account_id: '', // Reset account ID when changing provider
                      azure_workload_identity_config: newProvider === 'azure'
                        ? { tenant_id: '', client_id: '', subscription_id: '' }
                        : undefined,
                      azure_enabled: newProvider === 'azure',
                    })
                  }}
                  className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="aws">AWS</option>
                  <option value="gcp">GCP</option>
                  <option value="azure">Azure</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">
                {formData.provider === 'gcp' ? 'Project ID' : formData.provider === 'azure' ? 'Subscription ID' : 'Account ID'}
              </label>
              <input
                type="text"
                value={formData.account_id}
                onChange={(e) => {
                  const newAccountId = e.target.value
                  // For Azure, also update subscription_id in WIF config
                  if (formData.provider === 'azure') {
                    setFormData({
                      ...formData,
                      account_id: newAccountId,
                      azure_workload_identity_config: {
                        ...(formData.azure_workload_identity_config || { tenant_id: '', client_id: '', subscription_id: '' }),
                        subscription_id: newAccountId,
                      },
                    })
                  } else {
                    setFormData({ ...formData, account_id: newAccountId })
                  }
                }}
                className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder={formData.provider === 'gcp' ? 'my-gcp-project-id' : formData.provider === 'azure' ? '12345678-1234-1234-1234-123456789abc' : '123456789012'}
                required
              />
              {formData.provider === 'azure' && (
                <p className="text-xs text-gray-500 mt-1">Azure Subscription ID (GUID format)</p>
              )}
            </div>

            {/* Azure Workload Identity Federation Configuration */}
            {formData.provider === 'azure' && (
              <div className="space-y-4 p-4 bg-blue-900/20 border border-blue-700/50 rounded-lg">
                <h4 className="text-sm font-medium text-blue-300">Azure Workload Identity Federation</h4>
                <p className="text-xs text-gray-400">
                  Configure the Azure AD application for secure cross-cloud authentication.
                </p>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">
                      Tenant ID
                    </label>
                    <input
                      type="text"
                      value={formData.azure_workload_identity_config?.tenant_id || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        azure_workload_identity_config: {
                          ...(formData.azure_workload_identity_config || { tenant_id: '', client_id: '', subscription_id: formData.account_id }),
                          tenant_id: e.target.value,
                        },
                      })}
                      className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="12345678-1234-1234-1234-123456789abc"
                      required
                    />
                    <p className="text-xs text-gray-500 mt-1">Azure AD Directory (tenant) ID</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">
                      Client ID
                    </label>
                    <input
                      type="text"
                      value={formData.azure_workload_identity_config?.client_id || ''}
                      onChange={(e) => setFormData({
                        ...formData,
                        azure_workload_identity_config: {
                          ...(formData.azure_workload_identity_config || { tenant_id: '', client_id: '', subscription_id: formData.account_id }),
                          client_id: e.target.value,
                        },
                      })}
                      className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="12345678-1234-1234-1234-123456789abc"
                      required
                    />
                    <p className="text-xs text-gray-500 mt-1">Azure AD Application (client) ID</p>
                  </div>
                </div>
              </div>
            )}

            {/* Region Configuration */}
            <div>
              <RegionSelector
                provider={formData.provider}
                value={formData.region_config}
                onChange={(config) => setFormData({ ...formData, region_config: config })}
              />
            </div>

            <div className="flex justify-end space-x-3">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createMutation.isPending}
                className="btn-primary"
              >
                {createMutation.isPending ? 'Adding...' : 'Add Account'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Accounts List */}
      {!accounts?.length ? (
        <div className="text-center py-12 card">
          <Cloud className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-white">No cloud accounts</h3>
          <p className="mt-1 text-sm text-gray-400">Add your first cloud account to start scanning.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Scan limit warning banner */}
          {scanStatus && !scanStatus.unlimited && !scanStatus.can_scan && (
            <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4 flex items-center justify-between">
              <div className="flex items-center">
                <Clock className="h-5 w-5 text-yellow-400 mr-3" />
                <div>
                  <p className="text-sm font-medium text-yellow-400">
                    Weekly scan limit reached ({scanStatus.scans_used}/{scanStatus.scans_allowed})
                  </p>
                  {scanStatus.week_resets_at && (
                    <p className="text-xs text-yellow-400">
                      Resets on {new Date(scanStatus.week_resets_at).toLocaleDateString()}
                    </p>
                  )}
                </div>
              </div>
              <RouterLink
                to="/settings/billing"
                className="text-sm font-medium text-blue-400 hover:text-blue-300"
              >
                Upgrade for unlimited scans →
              </RouterLink>
            </div>
          )}

          {accounts.map((account) => (
            <AccountCard
              key={account.id}
              account={account}
              onConnect={() => setConnectingAccount(account)}
              onEdit={() => setEditingAccount(account)}
              onSchedule={() => setSchedulingAccount(account)}
              onScan={() => handleScan(account.id)}
              onDelete={() => deleteMutation.mutate(account.id)}
              isScanPending={isAccountScanning(account.id)}
              activeScan={getAccountScanProgress(account.id)}
              isDeletePending={deleteMutation.isPending}
              scanStatus={scanStatus}
            />
          ))}
        </div>
      )}

      {/* Credential Connection Wizard */}
      {connectingAccount && (
        <CredentialWizard
          cloudAccountId={connectingAccount.id}
          provider={connectingAccount.provider}
          accountName={connectingAccount.name}
          onClose={() => setConnectingAccount(null)}
          onSuccess={() => {
            setConnectingAccount(null)
            queryClient.invalidateQueries({ queryKey: ['accounts'] })
          }}
        />
      )}

      {/* Edit Account Modal */}
      {editingAccount && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-white">Edit Account: {editingAccount.name}</h2>
                <button
                  onClick={() => setEditingAccount(null)}
                  className="text-gray-400 hover:text-gray-300"
                >
                  &times;
                </button>
              </div>

              <div className="space-y-6">
                <RegionSelector
                  provider={editingAccount.provider}
                  accountId={editingAccount.id}
                  value={editingAccount.region_config || { mode: 'selected', regions: editingAccount.regions || [] }}
                  onChange={(config) => {
                    // Update local state for immediate feedback
                    setEditingAccount({
                      ...editingAccount,
                      region_config: config,
                    })
                  }}
                />

                <div className="flex justify-end space-x-3 pt-4 border-t">
                  <button
                    type="button"
                    onClick={() => setEditingAccount(null)}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      updateMutation.mutate({
                        id: editingAccount.id,
                        data: { region_config: editingAccount.region_config },
                      })
                    }}
                    disabled={updateMutation.isPending}
                    className="btn-primary"
                  >
                    {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Schedule Modal */}
      {schedulingAccount && (
        <ScheduleModal
          cloudAccountId={schedulingAccount.id}
          accountName={schedulingAccount.name}
          onClose={() => setSchedulingAccount(null)}
        />
      )}
    </div>
  )
}

// Account Card Component with credential status
function AccountCard({
  account,
  onConnect,
  onEdit,
  onSchedule,
  onScan,
  onDelete,
  isScanPending,
  activeScan,
  isDeletePending,
  scanStatus,
}: {
  account: CloudAccount
  onConnect: () => void
  onEdit: () => void
  onSchedule: () => void
  onScan: () => void
  onDelete: () => void
  isScanPending: boolean
  activeScan: Scan | null
  isDeletePending: boolean
  scanStatus?: ScanStatus
}) {
  // Check if scan is blocked due to limits
  const scanLimitReached = scanStatus && !scanStatus.unlimited && !scanStatus.can_scan
  // Fetch credential status for this account
  const { data: credential, isLoading: credentialLoading } = useQuery({
    queryKey: ['credentials', account.id],
    queryFn: () => credentialsApi.getCredential(account.id),
    retry: false,
    staleTime: 30000,
  })

  const getCredentialStatusBadge = () => {
    if (credentialLoading) {
      return (
        <span className="px-2 py-1 text-xs rounded-full bg-gray-700/30 text-gray-400">
          Loading...
        </span>
      )
    }

    if (!credential) {
      return (
        <span className="px-2 py-1 text-xs rounded-full bg-yellow-900/30 text-yellow-400 flex items-center">
          <AlertTriangle className="w-3 h-3 mr-1" />
          Not Connected
        </span>
      )
    }

    switch (credential.status) {
      case 'valid':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-green-900/30 text-green-400 flex items-center">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            Connected
          </span>
        )
      case 'pending':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-yellow-900/30 text-yellow-400 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Pending Validation
          </span>
        )
      case 'invalid':
      case 'expired':
      case 'permission_error':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-red-900/30 text-red-400 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            {credential.status === 'expired' ? 'Expired' : 'Connection Error'}
          </span>
        )
      default:
        return null
    }
  }

  const providerColor = account.provider === 'gcp'
    ? 'bg-blue-900/30 text-blue-400'
    : 'bg-orange-900/30 text-orange-400'

  return (
    <div className="card">
      {/* Main row - responsive layout */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        {/* Account info */}
        <div className="flex items-center min-w-0">
          <div className={`p-2 rounded-lg ${providerColor} shrink-0`}>
            <Cloud className="h-6 w-6" />
          </div>
          <div className="ml-4 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-semibold text-white truncate">{account.name}</h3>
              {getCredentialStatusBadge()}
            </div>
            <p className="text-sm text-gray-400 truncate">
              {account.provider.toUpperCase()} • {account.account_id}
            </p>
          </div>
        </div>

        {/* Action buttons - wrap on mobile */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-2 sm:shrink-0">
          <span className={`px-2 py-1 text-xs rounded-full ${
            account.is_active
              ? 'bg-green-900/30 text-green-400'
              : 'bg-gray-700/30 text-gray-400'
          }`}>
            {account.is_active ? 'Active' : 'Inactive'}
          </span>

          {/* Edit Regions Button */}
          <button
            onClick={onEdit}
            className="p-2 text-gray-400 hover:bg-gray-700 rounded-lg"
            title="Edit Regions"
          >
            <MapPin className="h-5 w-5" />
          </button>

          {/* Connect/Configure Button */}
          {!credential || credential.status !== 'valid' ? (
            <button
              onClick={onConnect}
              className="p-2 text-purple-400 hover:bg-gray-700 rounded-lg"
              title="Connect Account"
            >
              <Link className="h-5 w-5" />
            </button>
          ) : (
            <button
              onClick={onConnect}
              className="p-2 text-gray-400 hover:bg-gray-700 rounded-lg"
              title="Configure Connection"
            >
              <Settings className="h-5 w-5" />
            </button>
          )}

          {/* Schedule Button - configure recurring scans */}
          <button
            onClick={onSchedule}
            disabled={!credential || credential.status !== 'valid'}
            className={`p-2 rounded-lg transition-colors ${
              credential?.status === 'valid'
                ? 'text-cyan-400 hover:bg-gray-700'
                : 'text-gray-500 cursor-not-allowed'
            }`}
            title={credential?.status === 'valid' ? 'Configure Schedule' : 'Connect account first'}
          >
            <Calendar className="h-5 w-5" />
          </button>

          {/* Scan Button - only enabled if connected and within limits */}
          <button
            onClick={(e) => {
              e.stopPropagation()
              onScan()
            }}
            disabled={isScanPending || credentialLoading || !credential || credential.status !== 'valid' || scanLimitReached}
            className={`p-2 rounded-lg transition-all duration-150 ${
              credential?.status === 'valid' && !scanLimitReached && !credentialLoading
                ? 'text-blue-400 hover:bg-gray-700 hover:scale-110 active:scale-95 active:bg-gray-600'
                : 'text-gray-400 cursor-not-allowed'
            } ${isScanPending ? 'bg-gray-700' : ''}`}
            title={
              credentialLoading
                ? 'Loading credentials...'
                : isScanPending
                ? activeScan?.current_step || 'Scan in progress...'
                : scanLimitReached
                ? 'Weekly scan limit reached - upgrade for unlimited'
                : credential?.status === 'valid'
                ? 'Run Scan'
                : 'Connect account first'
            }
          >
            {isScanPending ? (
              <RefreshCw className="h-5 w-5 animate-spin text-blue-400" />
            ) : credentialLoading ? (
              <RefreshCw className="h-5 w-5 animate-spin text-gray-400" />
            ) : (
              <Play className="h-5 w-5" />
            )}
          </button>

          <button
            onClick={onDelete}
            disabled={isDeletePending}
            className="p-2 text-red-400 hover:bg-gray-700 rounded-lg"
            title="Delete"
          >
            <Trash2 className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Scan progress indicator - shown when scan is active */}
      {isScanPending && activeScan && (
        <div className="mt-3 p-3 bg-blue-900/20 border border-blue-700/50 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center text-sm text-blue-300">
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              <span>{activeScan.current_step || 'Scanning...'}</span>
            </div>
            <span className="text-sm font-medium text-blue-400">{activeScan.progress_percent}%</span>
          </div>
          <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${activeScan.progress_percent}%` }}
            />
          </div>
        </div>
      )}

      {/* Additional info row - responsive */}
      <div className="mt-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-sm text-gray-400">
        <div className="flex flex-wrap items-center gap-2 sm:gap-4">
          {/* Schedule indicator */}
          <ScheduleIndicator cloudAccountId={account.id} />

          {/* Region info */}
          <div className="flex items-center text-xs">
            <Globe className="h-3 w-3 mr-1" />
            {account.region_config ? (
              account.region_config.mode === 'all' ? (
                <span>All regions{account.region_config.excluded_regions?.length ? ` (-${account.region_config.excluded_regions.length})` : ''}</span>
              ) : account.region_config.mode === 'auto' ? (
                <span>{account.region_config.discovered_regions?.length || 0} discovered</span>
              ) : (
                <span>{account.region_config.regions?.length || 0} selected</span>
              )
            ) : account.regions?.length ? (
              <span>{account.regions.length} region{account.regions.length !== 1 ? 's' : ''}</span>
            ) : (
              <span className="text-yellow-400">No regions configured</span>
            )}
          </div>
          {account.last_scan_at && (
            <span className="text-xs">Last scan: {new Date(account.last_scan_at).toLocaleString()}</span>
          )}
          {credential?.credential_type && (
            <span className="text-xs bg-gray-700/30 px-2 py-0.5 rounded-sm">
              {credential.credential_type === 'aws_iam_role' ? 'IAM Role' :
               credential.credential_type === 'gcp_workload_identity' ? 'Workload Identity' :
               'Service Account Key'}
            </span>
          )}
        </div>
        {credential?.last_validated_at && (
          <span className="text-xs shrink-0">
            Validated: {new Date(credential.last_validated_at).toLocaleDateString()}
          </span>
        )}
      </div>

      {/* Warning for missing permissions */}
      {credential?.missing_permissions && credential.missing_permissions.length > 0 && (
        <div className="mt-3 p-2 bg-yellow-900/30 border border-yellow-700 rounded-lg">
          <p className="text-sm text-yellow-400">
            <AlertTriangle className="w-4 h-4 inline mr-1" />
            Missing {credential.missing_permissions.length} permission(s).
            <button onClick={onConnect} className="underline ml-1">Update credentials</button>
          </p>
        </div>
      )}
    </div>
  )
}
