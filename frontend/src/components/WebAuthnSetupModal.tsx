/**
 * WebAuthn/Passkey Setup Modal
 *
 * Guides users through registering a security key or passkey:
 * - Hardware keys (YubiKey, SoloKey)
 * - Platform authenticators (Touch ID, Windows Hello, Face ID)
 * - Passkeys (synced via iCloud, Google Password Manager)
 */

import { useState, useEffect } from 'react'
import {
  X,
  Shield,
  Key,
  Fingerprint,
  AlertCircle,
  Loader2,
  CheckCircle,
  Smartphone,
} from 'lucide-react'
import {
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  createCredential,
  PublicKeyCredentialCreationOptionsJSON,
} from '../utils/webauthn'

interface WebAuthnSetupModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
  type: 'user' | 'admin'
  getOptions: (
    deviceName: string,
    authenticatorType?: string
  ) => Promise<{ options: PublicKeyCredentialCreationOptionsJSON }>
  verifyCredential: (credential: unknown, deviceName: string) => Promise<void>
}

type Step = 'choose' | 'register' | 'success'

export default function WebAuthnSetupModal({
  isOpen,
  onClose,
  onSuccess,
  type: _type,
  getOptions,
  verifyCredential,
}: WebAuthnSetupModalProps) {
  const [step, setStep] = useState<Step>('choose')
  const [deviceName, setDeviceName] = useState('')
  const [authenticatorType, setAuthenticatorType] = useState<string | undefined>()
  const [error, setError] = useState('')
  const [isRegistering, setIsRegistering] = useState(false)
  const [hasPlatformAuthenticator, setHasPlatformAuthenticator] = useState(false)
  const [isSupported, setIsSupported] = useState(true)

  // Check WebAuthn support on mount
  useEffect(() => {
    const checkSupport = async () => {
      setIsSupported(isWebAuthnSupported())
      setHasPlatformAuthenticator(await isPlatformAuthenticatorAvailable())
    }
    checkSupport()
  }, [])

  // Reset state when modal closes
  useEffect(() => {
    if (!isOpen) {
      setStep('choose')
      setDeviceName('')
      setAuthenticatorType(undefined)
      setError('')
    }
  }, [isOpen])

  const handleRegister = async () => {
    if (!deviceName.trim()) {
      setError('Please enter a name for this security key')
      return
    }

    setError('')
    setIsRegistering(true)

    try {
      // Get registration options from server
      const { options } = await getOptions(deviceName.trim(), authenticatorType)

      // Create credential using browser API
      const credential = await createCredential(options)

      // Send credential to server for verification
      await verifyCredential(credential, deviceName.trim())

      setStep('success')
    } catch (err) {
      console.error('WebAuthn registration error:', err)
      if (err instanceof Error) {
        if (err.name === 'NotAllowedError') {
          setError('Registration was cancelled or timed out. Please try again.')
        } else if (err.name === 'InvalidStateError') {
          setError('This security key is already registered.')
        } else {
          setError(err.message || 'Registration failed. Please try again.')
        }
      } else {
        setError('Registration failed. Please try again.')
      }
    } finally {
      setIsRegistering(false)
    }
  }

  const selectAuthenticator = (type: 'platform' | 'cross-platform') => {
    setAuthenticatorType(type)
    setDeviceName(type === 'platform' ? 'This Device' : '')
    setStep('register')
  }

  const handleClose = () => {
    setStep('choose')
    setDeviceName('')
    setAuthenticatorType(undefined)
    setError('')
    onClose()
  }

  const handleComplete = () => {
    onSuccess()
    handleClose()
  }

  if (!isOpen) return null

  if (!isSupported) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-gray-800 rounded-xl border border-gray-700 shadow-xl max-w-md w-full mx-4 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-600 rounded-lg">
                <AlertCircle className="w-5 h-5 text-white" />
              </div>
              <h2 className="text-xl font-bold text-white">Not Supported</h2>
            </div>
            <button
              onClick={handleClose}
              className="p-1 text-gray-400 hover:text-white rounded-sm"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          <p className="text-gray-300 mb-6">
            Your browser doesn't support WebAuthn/Passkeys. Please use a modern browser
            like Chrome, Firefox, Safari, or Edge.
          </p>
          <button
            onClick={handleClose}
            className="w-full py-3 bg-gray-700 text-white font-medium rounded-lg hover:bg-gray-600"
          >
            Close
          </button>
        </div>
      </div>
    )
  }

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
              {step === 'success' ? 'Security Key Added' : 'Add Security Key'}
            </h2>
          </div>
          {step !== 'success' && (
            <button
              onClick={handleClose}
              className="p-1 text-gray-400 hover:text-white rounded-sm"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded-lg flex items-center gap-2 text-red-200">
            <AlertCircle className="w-5 h-5 shrink-0" />
            <span className="text-sm">{error}</span>
          </div>
        )}

        {/* Choose Authenticator Type */}
        {step === 'choose' && (
          <div className="space-y-4">
            <p className="text-gray-300 mb-4">
              Choose the type of security key you want to add:
            </p>

            {/* Platform Authenticator (Touch ID, Windows Hello) */}
            {hasPlatformAuthenticator && (
              <button
                onClick={() => selectAuthenticator('platform')}
                className="w-full p-4 bg-gray-700/50 border border-gray-600 rounded-lg hover:bg-gray-700 hover:border-blue-500 transition-colors text-left group"
              >
                <div className="flex items-start gap-4">
                  <div className="p-3 bg-blue-600/20 rounded-lg group-hover:bg-blue-600/30">
                    <Fingerprint className="w-6 h-6 text-blue-400" />
                  </div>
                  <div className="flex-1">
                    <h3 className="font-medium text-white mb-1">
                      This Device (Recommended)
                    </h3>
                    <p className="text-sm text-gray-400">
                      Use Touch ID, Face ID, or Windows Hello on this device
                    </p>
                  </div>
                </div>
              </button>
            )}

            {/* Hardware Security Key */}
            <button
              onClick={() => selectAuthenticator('cross-platform')}
              className="w-full p-4 bg-gray-700/50 border border-gray-600 rounded-lg hover:bg-gray-700 hover:border-blue-500 transition-colors text-left group"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-purple-600/20 rounded-lg group-hover:bg-purple-600/30">
                  <Key className="w-6 h-6 text-purple-400" />
                </div>
                <div className="flex-1">
                  <h3 className="font-medium text-white mb-1">Hardware Security Key</h3>
                  <p className="text-sm text-gray-400">
                    Use a YubiKey or other USB/NFC security key
                  </p>
                </div>
              </div>
            </button>

            {/* Passkey on Phone */}
            <button
              onClick={() => {
                setAuthenticatorType(undefined) // Let the browser choose
                setDeviceName('Passkey')
                setStep('register')
              }}
              className="w-full p-4 bg-gray-700/50 border border-gray-600 rounded-lg hover:bg-gray-700 hover:border-blue-500 transition-colors text-left group"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-green-600/20 rounded-lg group-hover:bg-green-600/30">
                  <Smartphone className="w-6 h-6 text-green-400" />
                </div>
                <div className="flex-1">
                  <h3 className="font-medium text-white mb-1">Passkey on Phone</h3>
                  <p className="text-sm text-gray-400">
                    Use a passkey saved on your phone (synced via iCloud or Google)
                  </p>
                </div>
              </div>
            </button>
          </div>
        )}

        {/* Register Step */}
        {step === 'register' && (
          <div className="space-y-6">
            <div className="text-center">
              {authenticatorType === 'platform' ? (
                <Fingerprint className="w-12 h-12 text-blue-400 mx-auto mb-4" />
              ) : (
                <Key className="w-12 h-12 text-purple-400 mx-auto mb-4" />
              )}
              <p className="text-gray-300">
                {authenticatorType === 'platform'
                  ? "You'll be prompted to use Touch ID, Face ID, or Windows Hello"
                  : 'Insert your security key and touch it when prompted'}
              </p>
            </div>

            {/* Device Name Input */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Device Name
              </label>
              <input
                type="text"
                value={deviceName}
                onChange={(e) => {
                  setDeviceName(e.target.value)
                  setError('')
                }}
                placeholder="e.g., YubiKey, MacBook Pro, Work Laptop"
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-hidden focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                disabled={isRegistering}
              />
              <p className="mt-1 text-xs text-gray-500">
                This helps you identify this key later
              </p>
            </div>

            {/* Buttons */}
            <div className="flex gap-3">
              <button
                onClick={() => setStep('choose')}
                disabled={isRegistering}
                className="flex-1 py-3 text-gray-400 hover:text-white font-medium rounded-lg hover:bg-gray-700 transition-colors disabled:opacity-50"
              >
                Back
              </button>
              <button
                onClick={handleRegister}
                disabled={!deviceName.trim() || isRegistering}
                className="flex-1 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isRegistering ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Waiting for key...
                  </>
                ) : (
                  'Register Key'
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
                Security Key Added
              </h3>
              <p className="text-gray-400">
                "{deviceName}" has been registered successfully. You can now use it to
                sign in.
              </p>
            </div>

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
