import { useState, useEffect } from 'react'
import { X, AlertTriangle, Loader2 } from 'lucide-react'

interface SuspendUserModalProps {
  user: { id: string; email: string; full_name: string } | null
  isOpen: boolean
  onClose: () => void
  onConfirm: (reason: string) => Promise<void>
  isLoading: boolean
}

const MIN_REASON_LENGTH = 10

export default function SuspendUserModal({
  user,
  isOpen,
  onClose,
  onConfirm,
  isLoading,
}: SuspendUserModalProps) {
  const [reason, setReason] = useState('')
  const [error, setError] = useState('')

  // Reset state when modal opens/closes
  useEffect(() => {
    if (isOpen) {
      setReason('')
      setError('')
    }
  }, [isOpen])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (reason.trim().length < MIN_REASON_LENGTH) {
      setError(`Please enter at least ${MIN_REASON_LENGTH} characters`)
      return
    }

    setError('')
    await onConfirm(reason.trim())
  }

  const handleClose = () => {
    if (!isLoading) {
      setReason('')
      setError('')
      onClose()
    }
  }

  if (!isOpen || !user) return null

  const isValid = reason.trim().length >= MIN_REASON_LENGTH

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-xl max-w-md w-full mx-4 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-600 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-white" />
            </div>
            <h2 className="text-xl font-bold text-white">Suspend User</h2>
          </div>
          <button
            onClick={handleClose}
            disabled={isLoading}
            className="p-1 text-gray-400 hover:text-white rounded-sm disabled:opacity-50"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Warning Message */}
        <div className="mb-6 p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg">
          <p className="text-yellow-200 text-sm">
            You are about to suspend:
          </p>
          <p className="text-white font-medium mt-1">
            {user.full_name} ({user.email})
          </p>
          <p className="text-yellow-200/80 text-sm mt-2">
            This will prevent the user from logging in until reactivated by an admin.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          {/* Reason Input */}
          <div className="mb-4">
            <label
              htmlFor="suspension-reason"
              className="block text-sm font-medium text-gray-300 mb-2"
            >
              Reason for suspension <span className="text-red-400">*</span>
            </label>
            <textarea
              id="suspension-reason"
              value={reason}
              onChange={(e) => {
                setReason(e.target.value)
                if (error) setError('')
              }}
              placeholder="Enter the reason for suspending this user..."
              rows={3}
              disabled={isLoading}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-hidden focus:ring-2 focus:ring-red-500 focus:border-red-500 disabled:opacity-50 resize-none"
              autoFocus
            />
            <p className="mt-1 text-xs text-gray-400">
              {reason.length}/{MIN_REASON_LENGTH} characters minimum
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded-lg">
              <p className="text-red-200 text-sm">{error}</p>
            </div>
          )}

          {/* Buttons */}
          <div className="flex gap-3">
            <button
              type="button"
              onClick={handleClose}
              disabled={isLoading}
              className="flex-1 py-3 text-gray-400 hover:text-white font-medium rounded-lg hover:bg-gray-700 transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!isValid || isLoading}
              className="flex-1 py-3 bg-red-600 text-white font-medium rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Suspending...
                </>
              ) : (
                'Suspend User'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
