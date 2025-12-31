import { useState, useEffect } from 'react'
import {
  Shield,
  Clock,
  Key,
  Globe,
  Plus,
  Trash2,
  CheckCircle,
  AlertCircle,
  Copy,
  RefreshCw,
  Save,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { securityApi, SecuritySettings, VerifiedDomain, DomainVerificationInfo } from '../services/securityApi'

export default function OrgSecurity() {
  const { token, user } = useAuth()
  const [settings, setSettings] = useState<SecuritySettings | null>(null)
  const [domains, setDomains] = useState<VerifiedDomain[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // Domain modal state
  const [showAddDomain, setShowAddDomain] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [addingDomain, setAddingDomain] = useState(false)

  // Verification modal state
  const [verifyingDomain, setVerifyingDomain] = useState<VerifiedDomain | null>(null)
  const [verificationInfo, setVerificationInfo] = useState<DomainVerificationInfo | null>(null)

  // Form state
  const [formData, setFormData] = useState<Partial<SecuritySettings>>({})

  const isOwner = user?.role === 'owner'

  useEffect(() => {
    loadData()
  }, [token])

  const loadData = async () => {
    if (!token) return
    setLoading(true)
    try {
      const [settingsData, domainsData] = await Promise.all([
        securityApi.getSettings(token),
        securityApi.getDomains(token),
      ])
      setSettings(settingsData)
      setFormData(settingsData)
      setDomains(domainsData)
    } catch (_error) {
      console.error('Failed to load security settings:', _error)
      setMessage({ type: 'error', text: 'Failed to load security settings' })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    if (!token || !isOwner) return
    setSaving(true)
    setMessage(null)

    try {
      const updates: Record<string, unknown> = {}
      const keys = [
        'require_mfa', 'mfa_grace_period_days', 'session_timeout_minutes',
        'idle_timeout_minutes', 'password_min_length', 'max_failed_login_attempts',
        'lockout_duration_minutes'
      ] as const

      for (const key of keys) {
        if (formData[key] !== settings?.[key]) {
          updates[key] = formData[key]
        }
      }

      if (Object.keys(updates).length === 0) {
        setMessage({ type: 'success', text: 'No changes to save' })
        setSaving(false)
        return
      }

      const updated = await securityApi.updateSettings(token, updates)
      setSettings(updated)
      setFormData(updated)
      setMessage({ type: 'success', text: 'Security settings updated successfully' })
    } catch (_error) {
      setMessage({ type: 'error', text: 'Failed to update security settings' })
    } finally {
      setSaving(false)
    }
  }

  const handleAddDomain = async () => {
    if (!token || !newDomain.trim()) return
    setAddingDomain(true)

    try {
      const domain = await securityApi.addDomain(token, newDomain.trim())
      setDomains([domain, ...domains])
      setNewDomain('')
      setShowAddDomain(false)
      setMessage({ type: 'success', text: 'Domain added. Follow verification instructions.' })

      // Show verification modal
      setVerifyingDomain(domain)
      const info = await securityApi.getDomainVerificationInfo(token, domain.id)
      setVerificationInfo(info)
    } catch (error: any) {
      setMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to add domain' })
    } finally {
      setAddingDomain(false)
    }
  }

  const handleVerifyDomain = async (domain: VerifiedDomain) => {
    if (!token) return

    try {
      const info = await securityApi.getDomainVerificationInfo(token, domain.id)
      setVerifyingDomain(domain)
      setVerificationInfo(info)
    } catch (_error) {
      setMessage({ type: 'error', text: 'Failed to get verification info' })
    }
  }

  const handleConfirmVerification = async () => {
    if (!token || !verifyingDomain) return

    try {
      const result = await securityApi.confirmDomainVerification(token, verifyingDomain.id)
      if (result.verified) {
        setMessage({ type: 'success', text: 'Domain verified successfully!' })
        loadData() // Reload to get updated domain
      } else {
        setVerificationInfo(result)
      }
    } catch (_error) {
      setMessage({ type: 'error', text: 'Verification failed. Please check your DNS records.' })
    }
  }

  const handleRemoveDomain = async (domain: VerifiedDomain) => {
    if (!token || !confirm(`Remove ${domain.domain}?`)) return

    try {
      await securityApi.removeDomain(token, domain.id)
      setDomains(domains.filter(d => d.id !== domain.id))
      setMessage({ type: 'success', text: 'Domain removed' })
    } catch (_error) {
      setMessage({ type: 'error', text: 'Failed to remove domain' })
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setMessage({ type: 'success', text: 'Copied to clipboard' })
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
      </div>
    )
  }

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Security Settings</h1>
        <p className="mt-1 text-sm text-gray-400">
          Configure security policies for your organization
        </p>
      </div>

      {message && (
        <div
          className={`mb-6 p-4 rounded-lg flex items-center ${
            message.type === 'success'
              ? 'bg-green-900/30 text-green-400 border border-green-700'
              : 'bg-red-900/30 text-red-400 border border-red-700'
          }`}
        >
          {message.type === 'success' ? (
            <CheckCircle className="h-5 w-5 mr-2" />
          ) : (
            <AlertCircle className="h-5 w-5 mr-2" />
          )}
          {message.text}
        </div>
      )}

      {/* MFA Settings */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Shield className="h-5 w-5 mr-2 text-gray-400" />
          Multi-Factor Authentication
        </h2>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <label className="font-medium text-gray-400">Require MFA for all members</label>
              <p className="text-sm text-gray-400">Members must enable MFA to access the organization</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={formData.require_mfa || false}
                onChange={(e) => setFormData({ ...formData, require_mfa: e.target.checked })}
                disabled={!isOwner}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-900 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>

          {formData.require_mfa && (
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">
                Grace period for existing members (days)
              </label>
              <input
                type="number"
                min={1}
                max={30}
                value={formData.mfa_grace_period_days || 7}
                onChange={(e) => setFormData({ ...formData, mfa_grace_period_days: parseInt(e.target.value) })}
                disabled={!isOwner}
                className="w-24 px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-700"
              />
            </div>
          )}
        </div>
      </div>

      {/* Session Settings */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Clock className="h-5 w-5 mr-2 text-gray-400" />
          Session Settings
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">
              Session timeout (minutes)
            </label>
            <select
              value={formData.session_timeout_minutes || 1440}
              onChange={(e) => setFormData({ ...formData, session_timeout_minutes: parseInt(e.target.value) })}
              disabled={!isOwner}
              className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-700"
            >
              <option value={60}>1 hour</option>
              <option value={240}>4 hours</option>
              <option value={480}>8 hours</option>
              <option value={1440}>24 hours</option>
              <option value={10080}>7 days</option>
              <option value={43200}>30 days</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">
              Idle timeout (minutes)
            </label>
            <select
              value={formData.idle_timeout_minutes || 60}
              onChange={(e) => setFormData({ ...formData, idle_timeout_minutes: parseInt(e.target.value) })}
              disabled={!isOwner}
              className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-700"
            >
              <option value={15}>15 minutes</option>
              <option value={30}>30 minutes</option>
              <option value={60}>1 hour</option>
              <option value={120}>2 hours</option>
              <option value={240}>4 hours</option>
            </select>
          </div>
        </div>
      </div>

      {/* Password Policy */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Key className="h-5 w-5 mr-2 text-gray-400" />
          Password Policy
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">
              Minimum password length
            </label>
            <input
              type="number"
              min={8}
              max={128}
              value={formData.password_min_length || 12}
              onChange={(e) => setFormData({ ...formData, password_min_length: parseInt(e.target.value) })}
              disabled={!isOwner}
              className="w-24 px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-700"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">
              Max failed login attempts
            </label>
            <input
              type="number"
              min={3}
              max={10}
              value={formData.max_failed_login_attempts || 5}
              onChange={(e) => setFormData({ ...formData, max_failed_login_attempts: parseInt(e.target.value) })}
              disabled={!isOwner}
              className="w-24 px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-700"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">
              Lockout duration (minutes)
            </label>
            <input
              type="number"
              min={5}
              max={1440}
              value={formData.lockout_duration_minutes || 30}
              onChange={(e) => setFormData({ ...formData, lockout_duration_minutes: parseInt(e.target.value) })}
              disabled={!isOwner}
              className="w-24 px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-700"
            />
          </div>
        </div>
      </div>

      {/* Save Button */}
      {isOwner && (
        <div className="flex justify-end mb-8">
          <button
            onClick={handleSave}
            disabled={saving}
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save className="h-4 w-4 mr-2" />
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      )}

      {/* Verified Domains */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center">
            <Globe className="h-5 w-5 mr-2 text-gray-400" />
            Verified Domains
          </h2>
          {isOwner && (
            <button
              onClick={() => setShowAddDomain(true)}
              className="inline-flex items-center px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <Plus className="h-4 w-4 mr-1" />
              Add Domain
            </button>
          )}
        </div>

        <p className="text-sm text-gray-400 mb-4">
          Verify your email domains to enable auto-join and SSO enforcement.
        </p>

        {domains.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            <Globe className="h-12 w-12 mx-auto mb-3 text-gray-400" />
            <p>No domains configured</p>
          </div>
        ) : (
          <div className="space-y-3">
            {domains.map((domain) => (
              <div
                key={domain.id}
                className="flex items-center justify-between p-4 bg-gray-700/30 rounded-lg"
              >
                <div className="flex items-center">
                  {domain.verified_at ? (
                    <CheckCircle className="h-5 w-5 text-green-400 mr-3" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-yellow-400 mr-3" />
                  )}
                  <div>
                    <div className="font-medium text-white">{domain.domain}</div>
                    <div className="text-sm text-gray-400">
                      {domain.verified_at
                        ? `Verified ${new Date(domain.verified_at).toLocaleDateString()}`
                        : 'Pending verification'}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {!domain.verified_at && isOwner && (
                    <button
                      onClick={() => handleVerifyDomain(domain)}
                      className="text-sm text-blue-400 hover:text-blue-300"
                    >
                      Verify
                    </button>
                  )}
                  {isOwner && (
                    <button
                      onClick={() => handleRemoveDomain(domain)}
                      className="p-1 text-gray-400 hover:text-red-400"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add Domain Modal */}
      {showAddDomain && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-xl max-w-md w-full mx-4 p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Add Domain</h3>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-400 mb-1">
                Domain name
              </label>
              <input
                type="text"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                placeholder="example.com"
                className="w-full px-3 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowAddDomain(false)}
                className="px-4 py-2 text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleAddDomain}
                disabled={addingDomain || !newDomain.trim()}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {addingDomain ? 'Adding...' : 'Add Domain'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Verification Modal */}
      {verifyingDomain && verificationInfo && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-xl max-w-lg w-full mx-4 p-6">
            <h3 className="text-lg font-semibold text-white mb-4">
              Verify {verifyingDomain.domain}
            </h3>

            {verificationInfo.verified ? (
              <div className="text-center py-4">
                <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-3" />
                <p className="text-green-400">{verificationInfo.message}</p>
              </div>
            ) : (
              <>
                <p className="text-sm text-gray-400 mb-4">{verificationInfo.instructions}</p>

                {verificationInfo.record_name && (
                  <div className="bg-gray-700/30 rounded-lg p-4 mb-4 space-y-3">
                    <div>
                      <span className="text-xs font-medium text-gray-400">Record Type</span>
                      <div className="font-mono text-sm text-white">{verificationInfo.record_type}</div>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-400">Name/Host</span>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 text-sm bg-gray-900 px-2 py-1 rounded border border-gray-700">
                          {verificationInfo.record_name}
                        </code>
                        <button
                          onClick={() => copyToClipboard(verificationInfo.record_name!)}
                          className="p-1 text-gray-400 hover:text-gray-400"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-400">Value</span>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 text-sm bg-gray-900 px-2 py-1 rounded border border-gray-700 break-all">
                          {verificationInfo.record_value}
                        </code>
                        <button
                          onClick={() => copyToClipboard(verificationInfo.record_value!)}
                          className="p-1 text-gray-400 hover:text-gray-400"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}

            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setVerifyingDomain(null)
                  setVerificationInfo(null)
                }}
                className="px-4 py-2 text-gray-400 hover:text-white"
              >
                Close
              </button>
              {!verificationInfo.verified && (
                <button
                  onClick={handleConfirmVerification}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Check Verification
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
