import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Cloud, Plus, Trash2, Play, RefreshCw, Link, CheckCircle2, AlertTriangle, Settings, Clock, Globe, MapPin } from 'lucide-react'
import { Link as RouterLink } from 'react-router-dom'
import { accountsApi, scansApi, credentialsApi, CloudAccount, scanStatusApi, ScanStatus, RegionConfig } from '../services/api'
import CredentialWizard from '../components/CredentialWizard'
import RegionSelector from '../components/RegionSelector'

export default function Accounts() {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [connectingAccount, setConnectingAccount] = useState<CloudAccount | null>(null)
  const [editingAccount, setEditingAccount] = useState<CloudAccount | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    provider: 'aws' as 'aws' | 'gcp',
    account_id: '',
    regions: [] as string[],
    region_config: {
      mode: 'selected',
      regions: ['eu-west-2'],  // A13E's primary region
    } as RegionConfig,
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
        provider: 'aws' as 'aws' | 'gcp',
        account_id: '',
        regions: [],
        region_config: { mode: 'selected', regions: ['eu-west-2'] },
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

  // Track which account is currently being scanned for per-account loading state
  const [scanningAccountId, setScanningAccountId] = useState<string | null>(null)
  // Feedback message for scan status
  const [scanFeedback, setScanFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  const scanMutation = useMutation({
    mutationFn: (accountId: string) => scansApi.create({ cloud_account_id: accountId }),
    onMutate: (accountId) => {
      // Immediate visual feedback
      setScanningAccountId(accountId)
      setScanFeedback(null) // Clear any previous feedback
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['scanStatus'] })
      setScanFeedback({ type: 'success', message: 'Scan started successfully! Check the Coverage page for results.' })
      // Auto-dismiss after 5 seconds
      setTimeout(() => setScanFeedback(null), 5000)
    },
    onError: (error: Error) => {
      setScanFeedback({ type: 'error', message: error.message || 'Failed to start scan. Please try again.' })
      // Auto-dismiss after 5 seconds
      setTimeout(() => setScanFeedback(null), 5000)
    },
    onSettled: () => {
      // Clear scanning state regardless of success/failure
      setScanningAccountId(null)
    },
  })

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
          <h1 className="text-2xl font-bold text-gray-900">Cloud Accounts</h1>
          <p className="text-gray-600">Manage your cloud accounts for scanning</p>
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
              ? 'bg-green-50 border border-green-200 text-green-800'
              : 'bg-red-50 border border-red-200 text-red-800'
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
            className="text-gray-500 hover:text-gray-700"
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
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Account Name
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder={formData.provider === 'gcp' ? 'My GCP Project' : 'My AWS Account'}
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Provider
                </label>
                <select
                  value={formData.provider}
                  onChange={(e) => setFormData({ ...formData, provider: e.target.value as 'aws' | 'gcp' })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="aws">AWS</option>
                  <option value="gcp">GCP</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {formData.provider === 'gcp' ? 'Project ID' : 'Account ID'}
              </label>
              <input
                type="text"
                value={formData.account_id}
                onChange={(e) => setFormData({ ...formData, account_id: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder={formData.provider === 'gcp' ? 'my-gcp-project-id' : '123456789012'}
                required
              />
            </div>

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
          <h3 className="mt-2 text-lg font-medium text-gray-900">No cloud accounts</h3>
          <p className="mt-1 text-sm text-gray-500">Add your first cloud account to start scanning.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Scan limit warning banner */}
          {scanStatus && !scanStatus.unlimited && !scanStatus.can_scan && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-center justify-between">
              <div className="flex items-center">
                <Clock className="h-5 w-5 text-yellow-600 mr-3" />
                <div>
                  <p className="text-sm font-medium text-yellow-800">
                    Weekly scan limit reached ({scanStatus.scans_used}/{scanStatus.scans_allowed})
                  </p>
                  {scanStatus.week_resets_at && (
                    <p className="text-xs text-yellow-600">
                      Resets on {new Date(scanStatus.week_resets_at).toLocaleDateString()}
                    </p>
                  )}
                </div>
              </div>
              <RouterLink
                to="/settings/billing"
                className="text-sm font-medium text-blue-600 hover:text-blue-700"
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
              onScan={() => scanMutation.mutate(account.id)}
              onDelete={() => deleteMutation.mutate(account.id)}
              isScanPending={scanningAccountId === account.id}
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
          <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold">Edit Account: {editingAccount.name}</h2>
                <button
                  onClick={() => setEditingAccount(null)}
                  className="text-gray-500 hover:text-gray-700"
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
    </div>
  )
}

// Account Card Component with credential status
function AccountCard({
  account,
  onConnect,
  onEdit,
  onScan,
  onDelete,
  isScanPending,
  isDeletePending,
  scanStatus,
}: {
  account: CloudAccount
  onConnect: () => void
  onEdit: () => void
  onScan: () => void
  onDelete: () => void
  isScanPending: boolean
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
        <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-600">
          Loading...
        </span>
      )
    }

    if (!credential) {
      return (
        <span className="px-2 py-1 text-xs rounded-full bg-yellow-100 text-yellow-800 flex items-center">
          <AlertTriangle className="w-3 h-3 mr-1" />
          Not Connected
        </span>
      )
    }

    switch (credential.status) {
      case 'valid':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-green-100 text-green-800 flex items-center">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            Connected
          </span>
        )
      case 'pending':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-yellow-100 text-yellow-800 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Pending Validation
          </span>
        )
      case 'invalid':
      case 'expired':
      case 'permission_error':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            {credential.status === 'expired' ? 'Expired' : 'Connection Error'}
          </span>
        )
      default:
        return null
    }
  }

  const providerColor = account.provider === 'gcp'
    ? 'bg-blue-100 text-blue-600'
    : 'bg-orange-100 text-orange-600'

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <div className={`p-2 rounded-lg ${providerColor}`}>
            <Cloud className="h-6 w-6" />
          </div>
          <div className="ml-4">
            <div className="flex items-center space-x-2">
              <h3 className="font-semibold text-gray-900">{account.name}</h3>
              {getCredentialStatusBadge()}
            </div>
            <p className="text-sm text-gray-500">
              {account.provider.toUpperCase()} • {account.account_id}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <span className={`px-2 py-1 text-xs rounded-full ${
            account.is_active
              ? 'bg-green-100 text-green-800'
              : 'bg-gray-100 text-gray-800'
          }`}>
            {account.is_active ? 'Active' : 'Inactive'}
          </span>

          {/* Edit Regions Button */}
          <button
            onClick={onEdit}
            className="p-2 text-gray-600 hover:bg-gray-50 rounded-lg"
            title="Edit Regions"
          >
            <MapPin className="h-5 w-5" />
          </button>

          {/* Connect/Configure Button */}
          {!credential || credential.status !== 'valid' ? (
            <button
              onClick={onConnect}
              className="p-2 text-purple-600 hover:bg-purple-50 rounded-lg"
              title="Connect Account"
            >
              <Link className="h-5 w-5" />
            </button>
          ) : (
            <button
              onClick={onConnect}
              className="p-2 text-gray-600 hover:bg-gray-50 rounded-lg"
              title="Configure Connection"
            >
              <Settings className="h-5 w-5" />
            </button>
          )}

          {/* Scan Button - only enabled if connected and within limits */}
          <button
            onClick={(e) => {
              e.stopPropagation()
              onScan()
            }}
            disabled={isScanPending || !credential || credential.status !== 'valid' || scanLimitReached}
            className={`p-2 rounded-lg transition-all duration-150 ${
              credential?.status === 'valid' && !scanLimitReached
                ? 'text-blue-600 hover:bg-blue-50 hover:scale-110 active:scale-95 active:bg-blue-100'
                : 'text-gray-400 cursor-not-allowed'
            } ${isScanPending ? 'bg-blue-50' : ''}`}
            title={
              isScanPending
                ? 'Scan in progress...'
                : scanLimitReached
                ? 'Weekly scan limit reached - upgrade for unlimited'
                : credential?.status === 'valid'
                ? 'Run Scan'
                : 'Connect account first'
            }
          >
            {isScanPending ? (
              <RefreshCw className="h-5 w-5 animate-spin text-blue-600" />
            ) : (
              <Play className="h-5 w-5" />
            )}
          </button>

          <button
            onClick={onDelete}
            disabled={isDeletePending}
            className="p-2 text-red-600 hover:bg-red-50 rounded-lg"
            title="Delete"
          >
            <Trash2 className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Additional info row */}
      <div className="mt-3 flex items-center justify-between text-sm text-gray-500">
        <div className="flex items-center space-x-4">
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
              <span className="text-yellow-600">No regions configured</span>
            )}
          </div>
          {account.last_scan_at && (
            <span>Last scanned: {new Date(account.last_scan_at).toLocaleString()}</span>
          )}
          {credential?.credential_type && (
            <span className="text-xs bg-gray-100 px-2 py-0.5 rounded">
              {credential.credential_type === 'aws_iam_role' ? 'IAM Role' :
               credential.credential_type === 'gcp_workload_identity' ? 'Workload Identity' :
               'Service Account Key'}
            </span>
          )}
        </div>
        {credential?.last_validated_at && (
          <span className="text-xs">
            Validated: {new Date(credential.last_validated_at).toLocaleDateString()}
          </span>
        )}
      </div>

      {/* Warning for missing permissions */}
      {credential?.missing_permissions && credential.missing_permissions.length > 0 && (
        <div className="mt-3 p-2 bg-yellow-50 border border-yellow-200 rounded-lg">
          <p className="text-sm text-yellow-800">
            <AlertTriangle className="w-4 h-4 inline mr-1" />
            Missing {credential.missing_permissions.length} permission(s).
            <button onClick={onConnect} className="underline ml-1">Update credentials</button>
          </p>
        </div>
      )}
    </div>
  )
}
