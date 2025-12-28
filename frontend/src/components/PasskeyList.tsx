/**
 * Passkey/Security Key List Component
 *
 * Displays registered WebAuthn credentials and allows users to:
 * - View registered keys with names and last used dates
 * - Add new security keys or passkeys
 * - Delete registered keys
 */

import { useState } from 'react'
import {
  Key,
  Fingerprint,
  Smartphone,
  Trash2,
  Plus,
  Shield,
  Loader2,
  AlertCircle,
} from 'lucide-react'
import WebAuthnSetupModal from './WebAuthnSetupModal'
import { isWebAuthnSupported } from '../utils/webauthn'

interface PasskeyCredential {
  credential_id: string
  device_name: string
  created_at: string
  last_used_at: string | null
}

interface PasskeyListProps {
  credentials: PasskeyCredential[]
  hasTotp?: boolean
  onAdd: () => void
  onDelete: (credentialId: string) => Promise<void>
  getOptions: (
    deviceName: string,
    authenticatorType?: string
  ) => Promise<{ options: unknown }>
  verifyCredential: (credential: unknown, deviceName: string) => Promise<void>
  onRefresh: () => void
}

export default function PasskeyList({
  credentials,
  hasTotp = false,
  onDelete,
  getOptions,
  verifyCredential,
  onRefresh,
}: PasskeyListProps) {
  const [showAddModal, setShowAddModal] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const isSupported = isWebAuthnSupported()

  const handleDelete = async (credentialId: string, deviceName: string) => {
    // Check if this is the last MFA method
    if (credentials.length === 1 && !hasTotp) {
      if (
        !confirm(
          `"${deviceName}" is your only MFA method. Removing it will disable MFA on your account. Continue?`
        )
      ) {
        return
      }
    } else {
      if (!confirm(`Remove "${deviceName}" from your account?`)) {
        return
      }
    }

    setError('')
    setDeletingId(credentialId)

    try {
      await onDelete(credentialId)
      onRefresh()
    } catch (err) {
      console.error('Failed to delete credential:', err)
      setError(err instanceof Error ? err.message : 'Failed to remove security key')
    } finally {
      setDeletingId(null)
    }
  }

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never'
    try {
      return new Date(dateStr).toLocaleDateString('en-GB', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      })
    } catch {
      return 'Unknown'
    }
  }

  const getKeyIcon = (deviceName: string) => {
    const name = deviceName.toLowerCase()
    if (
      name.includes('touch') ||
      name.includes('face') ||
      name.includes('windows hello') ||
      name.includes('this device')
    ) {
      return <Fingerprint className="w-5 h-5 text-blue-400" />
    }
    if (name.includes('phone') || name.includes('passkey') || name.includes('icloud')) {
      return <Smartphone className="w-5 h-5 text-green-400" />
    }
    return <Key className="w-5 h-5 text-purple-400" />
  }

  if (!isSupported) {
    return (
      <div className="bg-yellow-900/20 border border-yellow-700 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-medium text-yellow-400">
              WebAuthn Not Supported
            </h4>
            <p className="text-sm text-yellow-200/80 mt-1">
              Your browser doesn't support security keys or passkeys. Please use a
              modern browser like Chrome, Firefox, Safari, or Edge.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-medium text-white">Security Keys & Passkeys</h3>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Key
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="p-3 bg-red-900/50 border border-red-700 rounded-lg flex items-center gap-2 text-red-200">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Credentials List */}
      {credentials.length === 0 ? (
        <div className="bg-gray-700/30 border border-gray-600 border-dashed rounded-lg p-6 text-center">
          <Key className="w-10 h-10 text-gray-500 mx-auto mb-3" />
          <h4 className="font-medium text-gray-300 mb-1">No Security Keys</h4>
          <p className="text-sm text-gray-500 mb-4">
            Add a security key or passkey for stronger account protection
          </p>
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Your First Key
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {credentials.map((cred) => (
            <div
              key={cred.credential_id}
              className="bg-gray-700/50 border border-gray-600 rounded-lg p-4 flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 bg-gray-800 rounded-lg">
                  {getKeyIcon(cred.device_name)}
                </div>
                <div>
                  <h4 className="font-medium text-white">{cred.device_name}</h4>
                  <p className="text-sm text-gray-400">
                    Added {formatDate(cred.created_at)}
                    {cred.last_used_at && ` • Last used ${formatDate(cred.last_used_at)}`}
                  </p>
                </div>
              </div>
              <button
                onClick={() => handleDelete(cred.credential_id, cred.device_name)}
                disabled={deletingId === cred.credential_id}
                className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-900/20 rounded-lg transition-colors disabled:opacity-50"
                title="Remove this key"
              >
                {deletingId === cred.credential_id ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <Trash2 className="w-5 h-5" />
                )}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Info */}
      <div className="text-xs text-gray-500">
        <p>
          Security keys and passkeys provide the strongest protection against phishing
          attacks. You can register multiple keys for backup.
        </p>
      </div>

      {/* Add Modal */}
      <WebAuthnSetupModal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSuccess={() => {
          setShowAddModal(false)
          onRefresh()
        }}
        type="user"
        getOptions={getOptions as (deviceName: string, authenticatorType?: string) => Promise<{ options: import('../utils/webauthn').PublicKeyCredentialCreationOptionsJSON }>}
        verifyCredential={verifyCredential}
      />
    </div>
  )
}
