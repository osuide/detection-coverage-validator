import { useState, useEffect, FormEvent } from 'react'
import {
  Key,
  Plus,
  Copy,
  Check,
  AlertTriangle,
  Trash2,
  X,
  Shield,
  Info,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '../contexts/AuthContext'
import { apiKeysApi, APIKey, APIKeyCreated, ScopesResponse } from '../services/apiKeysApi'

export default function APIKeys() {
  const { accessToken } = useAuth()
  const [keys, setKeys] = useState<APIKey[]>([])
  const [scopesInfo, setScopesInfo] = useState<ScopesResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Create modal state
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>([])
  const [newKeyExpires, setNewKeyExpires] = useState<string>('')
  const [newKeyIpAllowlist, setNewKeyIpAllowlist] = useState<string>('')
  const [ipAllowlistEnabled, setIpAllowlistEnabled] = useState(false)
  const [isCreating, setIsCreating] = useState(false)

  // Newly created key state (to show the secret once)
  const [createdKey, setCreatedKey] = useState<APIKeyCreated | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    loadData()
  }, [accessToken])

  const loadData = async () => {
    if (!accessToken) return

    setIsLoading(true)
    setError(null)

    try {
      const [keysData, scopesData] = await Promise.all([
        apiKeysApi.getAPIKeys(accessToken),
        apiKeysApi.getScopes(accessToken),
      ])
      setKeys(keysData)
      setScopesInfo(scopesData)
    } catch (err) {
      console.error('Failed to load API keys:', err)
      setError('Failed to load API keys')
    } finally {
      setIsLoading(false)
    }
  }

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault()
    if (!accessToken) return

    setIsCreating(true)
    setError(null)

    try {
      // Parse IP allowlist if enabled
      const ipList = ipAllowlistEnabled && newKeyIpAllowlist.trim()
        ? newKeyIpAllowlist.split(/[,\n]/).map(ip => ip.trim()).filter(ip => ip)
        : undefined

      const result = await apiKeysApi.createAPIKey(accessToken, {
        name: newKeyName,
        scopes: newKeyScopes,
        expires_days: newKeyExpires ? parseInt(newKeyExpires) : undefined,
        ip_allowlist: ipList,
      })
      setCreatedKey(result)
      setShowCreateModal(false)
      setNewKeyName('')
      setNewKeyScopes([])
      setNewKeyExpires('')
      setNewKeyIpAllowlist('')
      setIpAllowlistEnabled(false)
      loadData()
    } catch (err: unknown) {
      const errorMessage = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        'Failed to create API key'
      setError(errorMessage)
    } finally {
      setIsCreating(false)
    }
  }

  const handleRevoke = async (keyId: string, keyName: string) => {
    if (!accessToken) return
    if (!confirm(`Are you sure you want to revoke "${keyName}"? This action cannot be undone.`)) return

    try {
      await apiKeysApi.revokeAPIKey(accessToken, keyId)
      loadData()
    } catch (err) {
      console.error('Failed to revoke API key:', err)
      setError('Failed to revoke API key')
    }
  }

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never'
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const toggleScope = (scope: string) => {
    setNewKeyScopes(prev =>
      prev.includes(scope)
        ? prev.filter(s => s !== scope)
        : [...prev, scope]
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-cyan-500 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">API Keys</h1>
          <p className="mt-1 text-sm text-gray-400">
            Manage API keys for programmatic access to the platform
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg shadow-sm text-white bg-cyan-600 hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500"
        >
          <Plus className="h-4 w-4 mr-2" />
          Create API Key
        </button>
      </div>

      {/* Error message */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-400 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Newly created key alert */}
      {createdKey && (
        <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4">
          <div className="flex items-start">
            <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5 mr-3 flex-shrink-0" />
            <div className="flex-1">
              <h3 className="text-sm font-medium text-yellow-400">
                Save your API key - you won't be able to see it again!
              </h3>
              <p className="mt-1 text-sm text-yellow-400">
                Make sure to copy your API key now. For security reasons, it won't be shown again.
              </p>
              <div className="mt-3 flex items-center space-x-2">
                <code className="flex-1 px-3 py-2 bg-white border border-yellow-700 rounded font-mono text-sm break-all">
                  {createdKey.key}
                </code>
                <button
                  onClick={() => copyToClipboard(createdKey.key)}
                  className="p-2 rounded-lg hover:bg-yellow-900/30"
                >
                  {copied ? (
                    <Check className="h-5 w-5 text-green-400" />
                  ) : (
                    <Copy className="h-5 w-5 text-yellow-400" />
                  )}
                </button>
              </div>
              <button
                onClick={() => setCreatedKey(null)}
                className="mt-3 text-sm text-yellow-400 hover:text-yellow-300 underline"
              >
                I've saved my key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* API Keys list */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700">
          <div className="flex items-center">
            <Key className="h-5 w-5 text-gray-400 mr-2" />
            <h2 className="text-lg font-medium text-white">Your API Keys</h2>
            <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-gray-700/30 text-gray-400 rounded-full">
              {keys.filter(k => k.is_active).length} active
            </span>
          </div>
        </div>

        {keys.length === 0 ? (
          <div className="p-12 text-center">
            <Key className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-sm font-medium text-white mb-1">No API keys</h3>
            <p className="text-sm text-gray-400">
              Create an API key to access the platform programmatically
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {keys.map((key) => (
              <div
                key={key.id}
                className={clsx(
                  'px-6 py-4',
                  !key.is_active && 'bg-gray-700/30 opacity-60'
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="h-10 w-10 rounded-lg bg-gray-700/30 flex items-center justify-center">
                      <Key className={clsx(
                        'h-5 w-5',
                        key.is_active ? 'text-gray-400' : 'text-gray-400'
                      )} />
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-medium text-white">{key.name}</span>
                        {!key.is_active && (
                          <span className="px-2 py-0.5 text-xs font-medium bg-red-900/30 text-red-400 rounded-full">
                            Revoked
                          </span>
                        )}
                      </div>
                      <div className="flex items-center space-x-4 text-xs text-gray-400 mt-1">
                        <span className="font-mono">{key.key_prefix}...</span>
                        {key.created_by_name && (
                          <span>Created by {key.created_by_name}</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-6">
                    {/* Scopes */}
                    <div className="text-right">
                      <div className="text-xs text-gray-400">Scopes</div>
                      <div className="text-sm text-white">
                        {key.scopes.length || 'All'}
                      </div>
                    </div>

                    {/* Last used */}
                    <div className="text-right">
                      <div className="text-xs text-gray-400">Last used</div>
                      <div className="text-sm text-white">
                        {key.last_used_at ? formatDate(key.last_used_at) : 'Never'}
                      </div>
                    </div>

                    {/* Usage */}
                    <div className="text-right">
                      <div className="text-xs text-gray-400">Requests</div>
                      <div className="text-sm text-white">{key.usage_count.toLocaleString()}</div>
                    </div>

                    {/* Expires */}
                    <div className="text-right">
                      <div className="text-xs text-gray-400">Expires</div>
                      <div className="text-sm text-white">
                        {key.expires_at ? formatDate(key.expires_at) : 'Never'}
                      </div>
                    </div>

                    {/* Actions */}
                    {key.is_active && (
                      <button
                        onClick={() => handleRevoke(key.id, key.name)}
                        className="p-2 text-red-400 hover:bg-red-900/30 rounded-lg"
                        title="Revoke API key"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Scope badges and IP restrictions */}
                <div className="mt-3 flex flex-wrap gap-1">
                  {key.scopes.length > 0 && key.scopes.map((scope) => (
                    <span
                      key={scope}
                      className="px-2 py-0.5 text-xs font-medium bg-gray-700/30 text-gray-400 rounded"
                    >
                      {scope}
                    </span>
                  ))}
                  {key.ip_allowlist && key.ip_allowlist.length > 0 && (
                    <span className="px-2 py-0.5 text-xs font-medium bg-blue-900/30 text-blue-400 rounded inline-flex items-center">
                      <Shield className="h-3 w-3 mr-1" />
                      {key.ip_allowlist.length} IP{key.ip_allowlist.length > 1 ? 's' : ''} allowed
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showCreateModal && scopesInfo && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h2 className="text-lg font-medium text-white">Create API Key</h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-gray-400 hover:text-gray-400"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreate} className="p-6 space-y-4">
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                  Name
                </label>
                <input
                  type="text"
                  id="name"
                  required
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-cyan-500 focus:border-cyan-500 sm:text-sm"
                  placeholder="e.g., CI/CD Pipeline, Monitoring Service"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">
                  Permissions
                </label>
                <div className="space-y-2 max-h-48 overflow-y-auto border border-gray-700 rounded-lg p-3">
                  {scopesInfo.scopes.map((scope) => (
                    <label
                      key={scope}
                      className="flex items-start cursor-pointer hover:bg-gray-700 p-1 rounded"
                    >
                      <input
                        type="checkbox"
                        checked={newKeyScopes.includes(scope)}
                        onChange={() => toggleScope(scope)}
                        className="h-4 w-4 mt-0.5 text-cyan-600 focus:ring-cyan-500 border-gray-300 rounded"
                      />
                      <div className="ml-2">
                        <span className="text-sm font-medium text-white">{scope}</span>
                        <p className="text-xs text-gray-400">{scopesInfo.descriptions[scope]}</p>
                      </div>
                    </label>
                  ))}
                </div>
                {newKeyScopes.length === 0 && (
                  <p className="mt-1 text-xs text-gray-400">
                    No scopes selected - key will have full access
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="expires" className="block text-sm font-medium text-gray-700">
                  Expiration (optional)
                </label>
                <select
                  id="expires"
                  value={newKeyExpires}
                  onChange={(e) => setNewKeyExpires(e.target.value)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-cyan-500 focus:border-cyan-500 sm:text-sm"
                >
                  <option value="">Never expires</option>
                  <option value="30">30 days</option>
                  <option value="60">60 days</option>
                  <option value="90">90 days</option>
                  <option value="180">180 days</option>
                  <option value="365">1 year</option>
                </select>
              </div>

              {/* IP Allowlist */}
              <div className="border border-gray-700 rounded-lg p-4 bg-gray-700/30">
                <label className="flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ipAllowlistEnabled}
                    onChange={(e) => setIpAllowlistEnabled(e.target.checked)}
                    className="h-4 w-4 text-cyan-600 focus:ring-cyan-500 border-gray-300 rounded"
                  />
                  <div className="ml-3 flex items-center">
                    <Shield className="h-4 w-4 text-gray-400 mr-2" />
                    <span className="text-sm font-medium text-gray-400">Restrict to specific IP addresses</span>
                  </div>
                </label>

                {ipAllowlistEnabled && (
                  <div className="mt-3">
                    <div className="flex items-start space-x-2 mb-2">
                      <Info className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                      <p className="text-xs text-gray-400">
                        Enter IP addresses or CIDR ranges, one per line or comma-separated.
                        The API key will only work from these addresses.
                      </p>
                    </div>
                    <textarea
                      value={newKeyIpAllowlist}
                      onChange={(e) => setNewKeyIpAllowlist(e.target.value)}
                      placeholder="e.g., 192.168.1.100&#10;10.0.0.0/24&#10;203.0.113.50"
                      rows={3}
                      className="block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-cyan-500 focus:border-cyan-500 sm:text-sm font-mono"
                    />
                  </div>
                )}
              </div>

              {error && (
                <div className="bg-red-900/30 border border-red-700 text-red-400 px-4 py-2 rounded-lg text-sm">
                  {error}
                </div>
              )}

              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-400 bg-white border border-gray-700 rounded-lg hover:bg-gray-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCreating || !newKeyName}
                  className="px-4 py-2 text-sm font-medium text-white bg-cyan-600 border border-transparent rounded-lg hover:bg-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isCreating ? 'Creating...' : 'Create Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
