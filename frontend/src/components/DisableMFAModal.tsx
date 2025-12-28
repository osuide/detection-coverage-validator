import { useState } from 'react'
import { X, ShieldOff, AlertTriangle, Loader2 } from 'lucide-react'

interface DisableMFAModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => Promise<void>
  orgRequiresMFA?: boolean
}

export default function DisableMFAModal({
  isOpen,
  onClose,
  onConfirm,
  orgRequiresMFA = false,
}: DisableMFAModalProps) {
  const [isDisabling, setIsDisabling] = useState(false)
  const [error, setError] = useState('')

  const handleConfirm = async () => {
    setIsDisabling(true)
    setError('')

    try {
      await onConfirm()
      onClose()
    } catch (err: unknown) {
      const errorMessage =
        err instanceof Error ? err.message : 'Failed to disable MFA. Please try again.'
      setError(errorMessage)
    } finally {
      setIsDisabling(false)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-xl max-w-md w-full mx-4 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-600 rounded-lg">
              <ShieldOff className="w-5 h-5 text-white" />
            </div>
            <h2 className="text-xl font-bold text-white">Disable Two-Factor Authentication</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-gray-400 hover:text-white rounded"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Org Requires MFA Warning */}
        {orgRequiresMFA ? (
          <div className="bg-red-900/50 border border-red-700 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium text-red-400">Cannot Disable MFA</h4>
                <p className="text-sm text-red-200/80 mt-1">
                  Your organisation requires all members to have MFA enabled.
                  Contact your organisation administrator to change this policy.
                </p>
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* Warning */}
            <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4 mb-6">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-medium text-yellow-400">Security Warning</h4>
                  <p className="text-sm text-yellow-200/80 mt-1">
                    Disabling two-factor authentication will make your account less
                    secure. Your account will only be protected by your password.
                  </p>
                </div>
              </div>
            </div>

            {/* Error Message */}
            {error && (
              <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded-lg text-red-200 text-sm">
                {error}
              </div>
            )}

            <p className="text-gray-300 mb-6">
              Are you sure you want to disable two-factor authentication?
            </p>
          </>
        )}

        {/* Buttons */}
        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-3 text-gray-400 hover:text-white font-medium rounded-lg hover:bg-gray-700 transition-colors"
          >
            Cancel
          </button>
          {!orgRequiresMFA && (
            <button
              onClick={handleConfirm}
              disabled={isDisabling}
              className="flex-1 py-3 bg-red-600 text-white font-medium rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {isDisabling ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Disabling...
                </>
              ) : (
                'Disable MFA'
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
