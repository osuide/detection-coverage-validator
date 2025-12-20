import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  UserPlus,
  Mail,
  Calendar,
  Key,
  AlertCircle,
  CheckCircle,
  XCircle,
  MoreVertical,
  Lock,
  Unlock,
  Trash2,
  Edit,
} from 'lucide-react';
import { useAdminAuthStore, adminApi } from '../../stores/adminAuthStore';

interface AdminUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
  created_by_email: string | null;
}

const ROLE_COLORS: Record<string, string> = {
  super_admin: 'bg-red-900/50 text-red-400 border-red-700',
  platform_admin: 'bg-purple-900/50 text-purple-400 border-purple-700',
  security_admin: 'bg-blue-900/50 text-blue-400 border-blue-700',
  support_admin: 'bg-green-900/50 text-green-400 border-green-700',
  billing_admin: 'bg-orange-900/50 text-orange-400 border-orange-700',
  readonly_admin: 'bg-gray-700 text-gray-300 border-gray-600',
};

const ROLE_LABELS: Record<string, string> = {
  super_admin: 'Super Admin',
  platform_admin: 'Platform Admin',
  security_admin: 'Security Admin',
  support_admin: 'Support Admin',
  billing_admin: 'Billing Admin',
  readonly_admin: 'Read Only',
};

export default function AdminAdmins() {
  const navigate = useNavigate();
  const { isAuthenticated, isInitialised, admin } = useAdminAuthStore();
  const [admins, setAdmins] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [actionMenu, setActionMenu] = useState<string | null>(null);

  // Create form state
  const [newAdmin, setNewAdmin] = useState({
    email: '',
    full_name: '',
    password: '',
    role: 'readonly_admin',
  });
  const [creating, setCreating] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [selectedAdmin, setSelectedAdmin] = useState<AdminUser | null>(null);
  const [newPassword, setNewPassword] = useState('');

  // Redirect if not authenticated
  useEffect(() => {
    if (isInitialised && !isAuthenticated) {
      navigate('/admin/login');
    }
  }, [isAuthenticated, isInitialised, navigate]);

  const fetchAdmins = async () => {
    setLoading(true);
    try {
      const response = await adminApi.get('/admins');
      setAdmins(response.data.admins);
    } catch (err) {
      const axiosError = err as { response?: { status?: number } };
      if (axiosError.response?.status === 403) {
        setError('You do not have permission to view admin users');
      } else {
        setError(err instanceof Error ? err.message : 'Failed to load admin users');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      fetchAdmins();
    }
  }, [isAuthenticated]);

  const createAdmin = async () => {
    if (!newAdmin.email || !newAdmin.full_name || !newAdmin.password) {
      setError('All fields are required');
      return;
    }

    if (newAdmin.password.length < 16) {
      setError('Password must be at least 16 characters');
      return;
    }

    setCreating(true);
    try {
      await adminApi.post('/admins', newAdmin);
      setShowCreateModal(false);
      setNewAdmin({ email: '', full_name: '', password: '', role: 'readonly_admin' });
      fetchAdmins();
    } catch (err) {
      const axiosError = err as { response?: { data?: { detail?: string } } };
      setError(axiosError.response?.data?.detail || 'Failed to create admin');
    } finally {
      setCreating(false);
    }
  };

  const toggleAdminStatus = async (adminId: string, currentStatus: boolean) => {
    try {
      await adminApi.put(`/admins/${adminId}/status`, { is_active: !currentStatus });
      setAdmins(admins.map(a =>
        a.id === adminId ? { ...a, is_active: !currentStatus } : a
      ));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update admin');
    }
    setActionMenu(null);
  };

  const changePassword = async () => {
    if (!selectedAdmin || !newPassword) return;

    if (newPassword.length < 16) {
      setError('Password must be at least 16 characters');
      return;
    }

    try {
      await adminApi.put(`/admins/${selectedAdmin.id}/password`, { password: newPassword });
      setShowPasswordModal(false);
      setSelectedAdmin(null);
      setNewPassword('');
      setError('');
      // Show success message
      alert('Password changed successfully');
    } catch (err) {
      const axiosError = err as { response?: { data?: { detail?: string } } };
      setError(axiosError.response?.data?.detail || 'Failed to change password');
    }
  };

  const openPasswordModal = (adminUser: AdminUser) => {
    setSelectedAdmin(adminUser);
    setNewPassword('');
    setShowPasswordModal(true);
    setActionMenu(null);
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const canManageAdmins = admin?.role === 'super_admin';

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-600 rounded-lg">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Admin Management</h1>
                <p className="text-sm text-gray-400">Manage platform administrators</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {canManageAdmins && (
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
                >
                  <UserPlus className="w-4 h-4" />
                  Add Admin
                </button>
              )}
              <button
                onClick={() => navigate('/admin/dashboard')}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Back to Dashboard
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded-lg flex items-center gap-2 text-red-200">
            <AlertCircle className="w-5 h-5" />
            <span>{error}</span>
            <button onClick={() => setError('')} className="ml-auto">
              <XCircle className="w-5 h-5" />
            </button>
          </div>
        )}

        {!canManageAdmins && (
          <div className="mb-6 p-4 bg-yellow-900/50 border border-yellow-700 rounded-lg flex items-center gap-2 text-yellow-200">
            <AlertCircle className="w-5 h-5" />
            <span>Only Super Admins can create or modify admin users.</span>
          </div>
        )}

        {/* Admins Table */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-visible">
          {loading ? (
            <div className="p-8 text-center text-gray-400">
              <div className="animate-spin w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full mx-auto mb-4" />
              Loading admin users...
            </div>
          ) : admins.length === 0 ? (
            <div className="p-8 text-center text-gray-400">
              <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No admin users found</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-900/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Admin
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Role
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    MFA
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Last Login
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Created
                  </th>
                  {canManageAdmins && (
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {admins.map((adminUser) => (
                  <tr key={adminUser.id} className="hover:bg-gray-700/50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-red-900/50 rounded-full flex items-center justify-center">
                          <Shield className="w-5 h-5 text-red-400" />
                        </div>
                        <div>
                          <div className="text-white font-medium">{adminUser.full_name}</div>
                          <div className="text-sm text-gray-400 flex items-center gap-1">
                            <Mail className="w-3 h-3" />
                            {adminUser.email}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`inline-flex items-center px-2 py-1 rounded border text-xs font-medium ${
                          ROLE_COLORS[adminUser.role] || ROLE_COLORS.readonly_admin
                        }`}
                      >
                        {ROLE_LABELS[adminUser.role] || adminUser.role}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                          adminUser.is_active
                            ? 'bg-green-900/50 text-green-400'
                            : 'bg-red-900/50 text-red-400'
                        }`}
                      >
                        {adminUser.is_active ? (
                          <>
                            <CheckCircle className="w-3 h-3" />
                            Active
                          </>
                        ) : (
                          <>
                            <XCircle className="w-3 h-3" />
                            Disabled
                          </>
                        )}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {adminUser.mfa_enabled ? (
                        <span className="inline-flex items-center gap-1 text-green-400 text-sm">
                          <Key className="w-4 h-4" />
                          Enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-yellow-400 text-sm">
                          <AlertCircle className="w-4 h-4" />
                          Not Set
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">
                      <div className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {formatDate(adminUser.last_login_at)}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">
                      <div>{formatDate(adminUser.created_at)}</div>
                      {adminUser.created_by_email && (
                        <div className="text-xs text-gray-500">
                          by {adminUser.created_by_email}
                        </div>
                      )}
                    </td>
                    {canManageAdmins && (
                      <td className="px-6 py-4 text-right">
                        <div className="relative inline-block">
                          <button
                            onClick={() => setActionMenu(actionMenu === adminUser.id ? null : adminUser.id)}
                            className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
                          >
                            <MoreVertical className="w-5 h-5" />
                          </button>

                          {actionMenu === adminUser.id && (
                            <div className="absolute right-0 mt-2 z-50 w-48 bg-gray-700 rounded-lg shadow-xl border border-gray-600 py-1">
                              <button
                                onClick={() => openPasswordModal(adminUser)}
                                className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-600 flex items-center gap-2"
                              >
                                <Key className="w-4 h-4" />
                                Change Password
                              </button>
                              <button
                                onClick={() => toggleAdminStatus(adminUser.id, adminUser.is_active)}
                                className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-600 flex items-center gap-2"
                              >
                                {adminUser.is_active ? (
                                  <>
                                    <Lock className="w-4 h-4" />
                                    Disable
                                  </>
                                ) : (
                                  <>
                                    <Unlock className="w-4 h-4" />
                                    Enable
                                  </>
                                )}
                              </button>
                              <button className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-600 flex items-center gap-2">
                                <Edit className="w-4 h-4" />
                                Edit Role
                              </button>
                              <button className="w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-gray-600 flex items-center gap-2">
                                <Trash2 className="w-4 h-4" />
                                Delete
                              </button>
                            </div>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </main>

      {/* Create Admin Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-md">
            <h2 className="text-xl font-bold text-white mb-4">Create Admin User</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={newAdmin.email}
                  onChange={(e) => setNewAdmin({ ...newAdmin, email: e.target.value })}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="admin@example.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  value={newAdmin.full_name}
                  onChange={(e) => setNewAdmin({ ...newAdmin, full_name: e.target.value })}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="John Doe"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Password (min 16 chars)
                </label>
                <input
                  type="password"
                  value={newAdmin.password}
                  onChange={(e) => setNewAdmin({ ...newAdmin, password: e.target.value })}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="Enter secure password"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Role
                </label>
                <select
                  value={newAdmin.role}
                  onChange={(e) => setNewAdmin({ ...newAdmin, role: e.target.value })}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                >
                  <option value="readonly_admin">Read Only</option>
                  <option value="support_admin">Support Admin</option>
                  <option value="billing_admin">Billing Admin</option>
                  <option value="security_admin">Security Admin</option>
                  <option value="platform_admin">Platform Admin</option>
                  <option value="super_admin">Super Admin</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={createAdmin}
                disabled={creating}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
              >
                {creating ? 'Creating...' : 'Create Admin'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Change Password Modal */}
      {showPasswordModal && selectedAdmin && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-md">
            <h2 className="text-xl font-bold text-white mb-2">Change Password</h2>
            <p className="text-gray-400 text-sm mb-4">
              Changing password for: <span className="text-white">{selectedAdmin.email}</span>
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  New Password (min 16 chars)
                </label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="Enter new password"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Password must be at least 16 characters long
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => {
                  setShowPasswordModal(false);
                  setSelectedAdmin(null);
                  setNewPassword('');
                }}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={changePassword}
                disabled={!newPassword || newPassword.length < 16}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Change Password
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
