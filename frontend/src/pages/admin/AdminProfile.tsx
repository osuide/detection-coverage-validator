import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  User,
  Mail,
  Shield,
  Key,
  ArrowLeft,
  ShieldCheck,
  Smartphone,
  AlertCircle,
} from 'lucide-react'
import { useAdminAuthStore, adminAuthActions } from '../../stores/adminAuthStore'
import MFASetupModal from '../../components/MFASetupModal'

export default function AdminProfile() {
  const navigate = useNavigate()
  const { isAuthenticated, isInitialised, admin } = useAdminAuthStore()
  const updateAdmin = useAdminAuthStore((state) => state.updateAdmin)

  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [showMFASetup, setShowMFASetup] = useState(false)

  // Redirect if not authenticated
  useEffect(() => {
    if (isInitialised && !isAuthenticated) {
      navigate('/admin/login')
    }
  }, [isAuthenticated, isInitialised, navigate])

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'super_admin':
        return 'bg-red-900/50 text-red-400 border-red-700'
      case 'platform_admin':
        return 'bg-purple-900/50 text-purple-400 border-purple-700'
      case 'security_admin':
        return 'bg-blue-900/50 text-blue-400 border-blue-700'
      case 'support_admin':
        return 'bg-green-900/50 text-green-400 border-green-700'
      case 'billing_admin':
        return 'bg-orange-900/50 text-orange-400 border-orange-700'
      default:
        return 'bg-gray-700 text-gray-300 border-gray-600'
    }
  }

  const getRoleLabel = (role: string) => {
    switch (role) {
      case 'super_admin':
        return 'Super Admin'
      case 'platform_admin':
        return 'Platform Admin'
      case 'security_admin':
        return 'Security Admin'
      case 'support_admin':
        return 'Support Admin'
      case 'billing_admin':
        return 'Billing Admin'
      case 'readonly_admin':
        return 'Read Only'
      default:
        return role
    }
  }

  if (!isInitialised || !admin) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/admin/dashboard')}
              className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-600 rounded-lg">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">My Profile</h1>
                <p className="text-sm text-gray-400">Manage your admin account settings</p>
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Messages */}
        {message && (
          <div
            className={`mb-6 p-4 rounded-lg flex items-center gap-2 ${
              message.type === 'success'
                ? 'bg-green-900/50 text-green-400 border border-green-700'
                : 'bg-red-900/50 text-red-400 border border-red-700'
            }`}
          >
            {message.type === 'error' && <AlertCircle className="w-5 h-5" />}
            {message.text}
          </div>
        )}

        {/* Account Overview */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
            <User className="h-5 w-5 mr-2 text-gray-400" />
            Account Overview
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
              <User className="h-5 w-5 text-gray-400 mr-3" />
              <div>
                <p className="text-xs text-gray-400">Full Name</p>
                <p className="font-medium text-white">{admin.full_name || 'Not set'}</p>
              </div>
            </div>
            <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
              <Mail className="h-5 w-5 text-gray-400 mr-3" />
              <div>
                <p className="text-xs text-gray-400">Email</p>
                <p className="font-medium text-white">{admin.email}</p>
              </div>
            </div>
            <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
              <Key className="h-5 w-5 text-gray-400 mr-3" />
              <div>
                <p className="text-xs text-gray-400">Role</p>
                <span
                  className={`inline-flex px-2 py-1 text-xs font-medium rounded border ${getRoleBadgeColor(
                    admin.role
                  )}`}
                >
                  {getRoleLabel(admin.role)}
                </span>
              </div>
            </div>
            <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
              <Smartphone className="h-5 w-5 text-gray-400 mr-3" />
              <div>
                <p className="text-xs text-gray-400">MFA Status</p>
                <span
                  className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                    admin.mfa_enabled
                      ? 'bg-green-900/30 text-green-400'
                      : 'bg-yellow-900/30 text-yellow-400'
                  }`}
                >
                  {admin.mfa_enabled ? 'Enabled' : 'Not Enabled'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Two-Factor Authentication */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
            <Shield className="h-5 w-5 mr-2 text-gray-400" />
            Two-Factor Authentication
          </h2>

          {admin.mfa_enabled ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-900/30 rounded-lg">
                  <ShieldCheck className="h-6 w-6 text-green-400" />
                </div>
                <div>
                  <p className="font-medium text-green-400">MFA is enabled</p>
                  <p className="text-sm text-gray-400">
                    Your admin account is protected with two-factor authentication
                  </p>
                </div>
              </div>
              {/* Admin MFA cannot be disabled for security */}
              <span className="text-sm text-gray-500">
                Contact Super Admin to reset
              </span>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Warning for admins without MFA */}
              <div className="bg-red-900/30 border border-red-700 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-medium text-red-400">MFA Required</h4>
                    <p className="text-sm text-red-200/80 mt-1">
                      Two-factor authentication is mandatory for all admin accounts in
                      staging and production environments. You must enable MFA to continue
                      using this account.
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-yellow-900/30 rounded-lg">
                    <Smartphone className="h-6 w-6 text-yellow-400" />
                  </div>
                  <div>
                    <p className="font-medium text-yellow-400">MFA is not enabled</p>
                    <p className="text-sm text-gray-400">
                      Set up two-factor authentication to secure your account
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setShowMFASetup(true)}
                  className="px-4 py-2 bg-red-600 text-white font-medium rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
                >
                  <ShieldCheck className="h-4 w-4" />
                  Enable MFA Now
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Password Change Notice */}
        {admin.requires_password_change && (
          <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium text-yellow-400">Password Change Required</h4>
                <p className="text-sm text-yellow-200/80 mt-1">
                  Your account requires a password change. Please update your password
                  through the admin management system.
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* MFA Setup Modal */}
      <MFASetupModal
        isOpen={showMFASetup}
        onClose={() => setShowMFASetup(false)}
        onSuccess={() => {
          setMessage({ type: 'success', text: 'Two-factor authentication has been enabled' })
          // Update admin state to reflect MFA is now enabled
          updateAdmin({ mfa_enabled: true })
        }}
        type="admin"
        setupMFA={adminAuthActions.setupMFA}
        verifyMFA={async (code) => {
          await adminAuthActions.enableMFA(code)
        }}
      />
    </div>
  )
}
