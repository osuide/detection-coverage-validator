import { useState, useEffect } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import {
  X,
  Shield,
  Copy,
  CheckCircle,
  AlertCircle,
  Loader2,
  Key,
  Smartphone,
} from 'lucide-react'

interface MFASetupModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: (backupCodes?: string[]) => void
  type: 'user' | 'admin'
  setupMFA: () => Promise<{ provisioning_uri: string; secret: string }>
  verifyMFA: (code: string) => Promise<{ backup_codes?: string[] } | void>
}

type Step = 'loading' | 'qr' | 'verify' | 'success'

export default function MFASetupModal({
  isOpen,
  onClose,
  onSuccess,
  type: _type, // Used to differentiate user vs admin flow (affects backup codes)
  setupMFA,
  verifyMFA,
}: MFASetupModalProps) {
  const [step, setStep] = useState<Step>('loading')
  const [provisioningUri, setProvisioningUri] = useState('')
  const [secret, setSecret] = useState('')
  const [verificationCode, setVerificationCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [error, setError] = useState('')
  const [isVerifying, setIsVerifying] = useState(false)
  const [copied, setCopied] = useState(false)
  const [backupCodesCopied, setBackupCodesCopied] = useState(false)

  // Start setup when modal opens - use useEffect to avoid state updates during render
  useEffect(() => {
    if (isOpen && step === 'loading' && !provisioningUri) {
      const startSetup = async () => {
        setError('')

        try {
          const data = await setupMFA()
          setProvisioningUri(data.provisioning_uri)
          setSecret(data.secret)
          setStep('qr')
        } catch (err) {
          setError('Failed to initialise MFA setup. Please try again.')
          setStep('qr') // Show error state
        }
      }

      startSetup()
    }
  }, [isOpen, step, provisioningUri, setupMFA])

  const handleVerify = async () => {
    if (verificationCode.length !== 6) {
      setError('Please enter a 6-digit code')
      return
    }

    setIsVerifying(true)
    setError('')

    try {
      const result = await verifyMFA(verificationCode)

      // User flow returns backup codes, admin flow doesn't
      if (result && 'backup_codes' in result && result.backup_codes) {
        setBackupCodes(result.backup_codes)
        setStep('success')
      } else {
        // Admin flow - no backup codes
        setStep('success')
      }
    } catch (err: unknown) {
      const errorMessage =
        err instanceof Error ? err.message : 'Invalid code. Please try again.'
      setError(errorMessage)
    } finally {
      setIsVerifying(false)
    }
  }

  const copySecret = () => {
    navigator.clipboard.writeText(secret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'))
    setBackupCodesCopied(true)
    setTimeout(() => setBackupCodesCopied(false), 2000)
  }

  const handleClose = () => {
    // Reset state
    setStep('loading')
    setProvisioningUri('')
    setSecret('')
    setVerificationCode('')
    setBackupCodes([])
    setError('')
    onClose()
  }

  const handleComplete = () => {
    onSuccess(backupCodes.length > 0 ? backupCodes : undefined)
    handleClose()
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-xl max-w-md w-full mx-4 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600 rounded-lg">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <h2 className="text-xl font-bold text-white">
              {step === 'success' ? 'MFA Enabled' : 'Set Up Two-Factor Authentication'}
            </h2>
          </div>
          {step !== 'success' && (
            <button
              onClick={handleClose}
              className="p-1 text-gray-400 hover:text-white rounded"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded-lg flex items-center gap-2 text-red-200">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <span className="text-sm">{error}</span>
          </div>
        )}

        {/* Loading State */}
        {step === 'loading' && (
          <div className="py-12 text-center">
            <Loader2 className="w-8 h-8 animate-spin text-blue-500 mx-auto mb-4" />
            <p className="text-gray-400">Initialising MFA setup...</p>
          </div>
        )}

        {/* QR Code Step */}
        {step === 'qr' && provisioningUri && (
          <div className="space-y-6">
            <div className="text-center">
              <p className="text-gray-300 mb-4">
                Scan this QR code with your authenticator app (Google Authenticator,
                Authy, 1Password, etc.)
              </p>

              {/* QR Code */}
              <div className="bg-white p-4 rounded-lg inline-block mb-4">
                <QRCodeSVG value={provisioningUri} size={200} level="M" />
              </div>
            </div>

            {/* Manual Entry */}
            <div className="bg-gray-700/50 rounded-lg p-4">
              <p className="text-sm text-gray-400 mb-2">
                Can't scan? Enter this code manually:
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-gray-900 px-3 py-2 rounded text-sm font-mono text-white break-all">
                  {secret}
                </code>
                <button
                  onClick={copySecret}
                  className="p-2 text-gray-400 hover:text-white rounded hover:bg-gray-700"
                  title="Copy to clipboard"
                >
                  {copied ? (
                    <CheckCircle className="w-5 h-5 text-green-400" />
                  ) : (
                    <Copy className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            {/* Next Button */}
            <button
              onClick={() => setStep('verify')}
              className="w-full py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
            >
              I've added it to my authenticator
            </button>
          </div>
        )}

        {/* Verify Step */}
        {step === 'verify' && (
          <div className="space-y-6">
            <div className="text-center">
              <Smartphone className="w-12 h-12 text-blue-400 mx-auto mb-4" />
              <p className="text-gray-300">
                Enter the 6-digit code from your authenticator app to verify setup
              </p>
            </div>

            {/* Code Input */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Verification Code
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={verificationCode}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, '')
                  setVerificationCode(value)
                  setError('')
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && verificationCode.length === 6) {
                    handleVerify()
                  }
                }}
                placeholder="000000"
                className="w-full px-4 py-3 text-center text-2xl font-mono tracking-widest bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                autoFocus
              />
            </div>

            {/* Buttons */}
            <div className="flex gap-3">
              <button
                onClick={() => setStep('qr')}
                className="flex-1 py-3 text-gray-400 hover:text-white font-medium rounded-lg hover:bg-gray-700 transition-colors"
              >
                Back
              </button>
              <button
                onClick={handleVerify}
                disabled={verificationCode.length !== 6 || isVerifying}
                className="flex-1 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isVerifying ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Verifying...
                  </>
                ) : (
                  'Verify & Enable'
                )}
              </button>
            </div>
          </div>
        )}

        {/* Success Step */}
        {step === 'success' && (
          <div className="space-y-6">
            <div className="text-center">
              <div className="w-16 h-16 bg-green-600 rounded-full flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="w-8 h-8 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">
                Two-Factor Authentication Enabled
              </h3>
              <p className="text-gray-400">
                Your account is now protected with MFA
              </p>
            </div>

            {/* Backup Codes (User flow only) */}
            {backupCodes.length > 0 && (
              <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4">
                <div className="flex items-start gap-3 mb-3">
                  <Key className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-medium text-yellow-400">
                      Save Your Backup Codes
                    </h4>
                    <p className="text-sm text-yellow-200/80 mt-1">
                      Store these codes securely. Each code can only be used once if
                      you lose access to your authenticator.
                    </p>
                  </div>
                </div>

                <div className="bg-gray-900 rounded p-3 mb-3">
                  <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                    {backupCodes.map((code, index) => (
                      <div key={index} className="text-gray-300">
                        {code}
                      </div>
                    ))}
                  </div>
                </div>

                <button
                  onClick={copyBackupCodes}
                  className="w-full py-2 text-sm bg-gray-700 text-gray-300 rounded hover:bg-gray-600 flex items-center justify-center gap-2"
                >
                  {backupCodesCopied ? (
                    <>
                      <CheckCircle className="w-4 h-4 text-green-400" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      Copy Backup Codes
                    </>
                  )}
                </button>
              </div>
            )}

            {/* Done Button */}
            <button
              onClick={handleComplete}
              className="w-full py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
            >
              Done
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
