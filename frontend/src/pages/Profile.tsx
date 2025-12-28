import { useState } from 'react'
import { User, Mail, Building, Shield, Save, Key, Smartphone, ShieldCheck, ShieldOff } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useAuthStore } from '../stores/authStore'
import { authApi } from '../services/authApi'
import MFASetupModal from '../components/MFASetupModal'
import DisableMFAModal from '../components/DisableMFAModal'

export default function Profile() {
  const { user, organization, token } = useAuth()
  const updateUser = useAuthStore((state) => state.updateUser)
  const [fullName, setFullName] = useState(user?.full_name || '')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // MFA modal state
  const [showMFASetup, setShowMFASetup] = useState(false)
  const [showDisableMFA, setShowDisableMFA] = useState(false)

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setMessage(null)

    try {
      const response = await fetch('/api/v1/auth/me', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ full_name: fullName }),
      })

      if (response.ok) {
        setMessage({ type: 'success', text: 'Profile updated successfully' })
      } else {
        const data = await response.json()
        setMessage({ type: 'error', text: data.detail || 'Failed to update profile' })
      }
    } catch {
      setMessage({ type: 'error', text: 'Failed to update profile' })
    } finally {
      setSaving(false)
    }
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()

    if (newPassword !== confirmPassword) {
      setMessage({ type: 'error', text: 'New passwords do not match' })
      return
    }

    if (newPassword.length < 8) {
      setMessage({ type: 'error', text: 'Password must be at least 8 characters' })
      return
    }

    setSaving(true)
    setMessage(null)

    try {
      const response = await fetch('/api/v1/auth/me/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      })

      if (response.ok) {
        setMessage({ type: 'success', text: 'Password changed successfully' })
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')
      } else {
        const data = await response.json()
        setMessage({ type: 'error', text: data.detail || 'Failed to change password' })
      }
    } catch {
      setMessage({ type: 'error', text: 'Failed to change password' })
    } finally {
      setSaving(false)
    }
  }

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'owner':
        return 'bg-purple-900/30 text-purple-400'
      case 'admin':
        return 'bg-blue-900/30 text-blue-400'
      case 'member':
        return 'bg-green-900/30 text-green-400'
      case 'viewer':
        return 'bg-gray-700/30 text-gray-400'
      default:
        return 'bg-gray-700/30 text-gray-400'
    }
  }

  return (
    <div className="max-w-4xl">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Profile Settings</h1>
        <p className="mt-1 text-sm text-gray-400">
          Manage your account information and security settings
        </p>
      </div>

      {message && (
        <div
          className={`mb-6 p-4 rounded-lg ${
            message.type === 'success'
              ? 'bg-green-50 text-green-800 border border-green-200'
              : 'bg-red-50 text-red-800 border border-red-200'
          }`}
        >
          {message.text}
        </div>
      )}

      {/* Account Overview */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <User className="h-5 w-5 mr-2 text-gray-400" />
          Account Overview
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
            <Mail className="h-5 w-5 text-gray-400 mr-3" />
            <div>
              <p className="text-xs text-gray-400">Email</p>
              <p className="font-medium text-white">{user?.email}</p>
            </div>
          </div>
          <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
            <Building className="h-5 w-5 text-gray-400 mr-3" />
            <div>
              <p className="text-xs text-gray-400">Organization</p>
              <p className="font-medium text-white">{organization?.name}</p>
            </div>
          </div>
          <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
            <Shield className="h-5 w-5 text-gray-400 mr-3" />
            <div>
              <p className="text-xs text-gray-400">Role</p>
              <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getRoleBadgeColor(user?.role || '')}`}>
                {user?.role?.charAt(0).toUpperCase()}{user?.role?.slice(1)}
              </span>
            </div>
          </div>
          <div className="flex items-center p-4 bg-gray-700/30 rounded-lg">
            <Smartphone className="h-5 w-5 text-gray-400 mr-3" />
            <div>
              <p className="text-xs text-gray-400">MFA Status</p>
              <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                user?.mfa_enabled ? 'bg-green-900/30 text-green-400' : 'bg-yellow-900/30 text-yellow-400'
              }`}>
                {user?.mfa_enabled ? 'Enabled' : 'Not Enabled'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Two-Factor Authentication */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Shield className="h-5 w-5 mr-2 text-gray-400" />
          Two-Factor Authentication
        </h2>

        {user?.mfa_enabled ? (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-900/30 rounded-lg">
                <ShieldCheck className="h-6 w-6 text-green-400" />
              </div>
              <div>
                <p className="font-medium text-green-400">MFA is enabled</p>
                <p className="text-sm text-gray-400">
                  Your account is protected with two-factor authentication
                </p>
              </div>
            </div>
            <button
              onClick={() => setShowDisableMFA(true)}
              className="px-4 py-2 text-red-400 hover:text-red-300 font-medium rounded-lg hover:bg-red-900/20 transition-colors flex items-center gap-2"
            >
              <ShieldOff className="h-4 w-4" />
              Disable MFA
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-yellow-900/30 rounded-lg">
                <Smartphone className="h-6 w-6 text-yellow-400" />
              </div>
              <div>
                <p className="font-medium text-yellow-400">MFA is not enabled</p>
                <p className="text-sm text-gray-400">
                  Add an extra layer of security to your account
                </p>
              </div>
            </div>
            <button
              onClick={() => setShowMFASetup(true)}
              className="px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
            >
              <ShieldCheck className="h-4 w-4" />
              Enable MFA
            </button>
          </div>
        )}
      </div>

      {/* Update Profile */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <User className="h-5 w-5 mr-2 text-gray-400" />
          Update Profile
        </h2>
        <form onSubmit={handleUpdateProfile}>
          <div className="mb-4">
            <label htmlFor="fullName" className="block text-sm font-medium text-gray-300 mb-1">
              Full Name
            </label>
            <input
              type="text"
              id="fullName"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full px-4 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Enter your full name"
            />
          </div>
          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save className="h-4 w-4 mr-2" />
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </form>
      </div>

      {/* Change Password */}
      <div className="bg-gray-800 rounded-xl shadow-sm border border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Key className="h-5 w-5 mr-2 text-gray-400" />
          Change Password
        </h2>
        <form onSubmit={handleChangePassword}>
          <div className="space-y-4">
            <div>
              <label htmlFor="currentPassword" className="block text-sm font-medium text-gray-300 mb-1">
                Current Password
              </label>
              <input
                type="password"
                id="currentPassword"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-4 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter current password"
                required
              />
            </div>
            <div>
              <label htmlFor="newPassword" className="block text-sm font-medium text-gray-300 mb-1">
                New Password
              </label>
              <input
                type="password"
                id="newPassword"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-4 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter new password"
                required
                minLength={8}
              />
            </div>
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-300 mb-1">
                Confirm New Password
              </label>
              <input
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Confirm new password"
                required
                minLength={8}
              />
            </div>
          </div>
          <button
            type="submit"
            disabled={saving || !currentPassword || !newPassword || !confirmPassword}
            className="mt-4 inline-flex items-center px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Key className="h-4 w-4 mr-2" />
            {saving ? 'Changing...' : 'Change Password'}
          </button>
        </form>
      </div>

      {/* MFA Setup Modal */}
      <MFASetupModal
        isOpen={showMFASetup}
        onClose={() => setShowMFASetup(false)}
        onSuccess={() => {
          setMessage({ type: 'success', text: 'Two-factor authentication has been enabled' })
          // Update user state to reflect MFA is now enabled
          updateUser({ mfa_enabled: true })
        }}
        type="user"
        setupMFA={() => authApi.setupMFA(token!)}
        verifyMFA={(code) => authApi.verifyMFASetup(token!, code)}
      />

      {/* Disable MFA Modal */}
      <DisableMFAModal
        isOpen={showDisableMFA}
        onClose={() => setShowDisableMFA(false)}
        onConfirm={async () => {
          await authApi.disableMFA(token!)
          setMessage({ type: 'success', text: 'Two-factor authentication has been disabled' })
          // Update user state to reflect MFA is now disabled
          updateUser({ mfa_enabled: false })
        }}
        orgRequiresMFA={organization?.require_mfa}
      />
    </div>
  )
}
