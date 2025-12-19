import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Users,
  Search,
  Shield,
  Ban,
  CheckCircle,
  Mail,
  Calendar,
  Building2,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  UserX,
  UserCheck,
} from 'lucide-react';

interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  email_verified: boolean;
  created_at: string;
  last_login_at: string | null;
  organizations: Array<{
    id: string;
    name: string;
    role: string;
  }>;
}

interface UsersResponse {
  users: User[];
  total: number;
  page: number;
  per_page: number;
}

export default function AdminUsers() {
  const navigate = useNavigate();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('admin_token');
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '20',
      });
      if (searchQuery) {
        params.append('search', searchQuery);
      }

      const response = await fetch(`/api/v1/admin/users?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.status === 401) {
        navigate('/admin/login');
        return;
      }

      if (!response.ok) throw new Error('Failed to fetch users');

      const data: UsersResponse = await response.json();
      setUsers(data.users);
      setTotal(data.total);
      setTotalPages(Math.ceil(data.total / data.per_page));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [page]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchUsers();
  };

  const toggleUserStatus = async (userId: string, currentStatus: boolean) => {
    setActionLoading(userId);
    try {
      const token = localStorage.getItem('admin_token');
      const response = await fetch(`/api/v1/admin/users/${userId}/status`, {
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ is_active: !currentStatus }),
      });

      if (!response.ok) throw new Error('Failed to update user status');

      setUsers(users.map(u =>
        u.id === userId ? { ...u, is_active: !currentStatus } : u
      ));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    } finally {
      setActionLoading(null);
    }
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

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-600 rounded-lg">
                <Users className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">User Management</h1>
                <p className="text-sm text-gray-400">Manage platform users</p>
              </div>
            </div>
            <button
              onClick={() => navigate('/admin/dashboard')}
              className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
            >
              Back to Dashboard
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded-lg flex items-center gap-2 text-red-200">
            <AlertCircle className="w-5 h-5" />
            <span>{error}</span>
          </div>
        )}

        {/* Search */}
        <div className="mb-6">
          <form onSubmit={handleSearch} className="flex gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by email or name..."
                className="w-full pl-10 pr-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
              />
            </div>
            <button
              type="submit"
              className="px-6 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
            >
              Search
            </button>
          </form>
        </div>

        {/* Stats */}
        <div className="mb-6 flex items-center gap-4 text-sm text-gray-400">
          <span>Total: {total} users</span>
          <span>Page {page} of {totalPages}</span>
        </div>

        {/* Users Table */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          {loading ? (
            <div className="p-8 text-center text-gray-400">
              <div className="animate-spin w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full mx-auto mb-4" />
              Loading users...
            </div>
          ) : users.length === 0 ? (
            <div className="p-8 text-center text-gray-400">
              <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No users found</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-900/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Organizations
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Last Login
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {users.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-700/50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-gray-700 rounded-full flex items-center justify-center">
                          <span className="text-lg font-medium text-white">
                            {user.full_name.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <div className="text-white font-medium">{user.full_name}</div>
                          <div className="text-sm text-gray-400 flex items-center gap-1">
                            <Mail className="w-3 h-3" />
                            {user.email}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col gap-1">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                            user.is_active
                              ? 'bg-green-900/50 text-green-400'
                              : 'bg-red-900/50 text-red-400'
                          }`}
                        >
                          {user.is_active ? (
                            <CheckCircle className="w-3 h-3" />
                          ) : (
                            <Ban className="w-3 h-3" />
                          )}
                          {user.is_active ? 'Active' : 'Suspended'}
                        </span>
                        {user.email_verified && (
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-blue-900/50 text-blue-400">
                            <Shield className="w-3 h-3" />
                            Verified
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {user.organizations.length === 0 ? (
                          <span className="text-gray-500 text-sm">None</span>
                        ) : (
                          user.organizations.slice(0, 2).map((org) => (
                            <span
                              key={org.id}
                              className="inline-flex items-center gap-1 px-2 py-1 bg-gray-700 rounded text-xs text-gray-300"
                            >
                              <Building2 className="w-3 h-3" />
                              {org.name}
                              <span className="text-gray-500">({org.role})</span>
                            </span>
                          ))
                        )}
                        {user.organizations.length > 2 && (
                          <span className="text-xs text-gray-500">
                            +{user.organizations.length - 2} more
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">
                      <div className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {formatDate(user.last_login_at)}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">
                      {formatDate(user.created_at)}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => toggleUserStatus(user.id, user.is_active)}
                        disabled={actionLoading === user.id}
                        className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                          user.is_active
                            ? 'bg-red-900/50 text-red-400 hover:bg-red-900'
                            : 'bg-green-900/50 text-green-400 hover:bg-green-900'
                        } disabled:opacity-50`}
                      >
                        {actionLoading === user.id ? (
                          <div className="animate-spin w-4 h-4 border-2 border-current border-t-transparent rounded-full" />
                        ) : user.is_active ? (
                          <>
                            <UserX className="w-4 h-4" />
                            Suspend
                          </>
                        ) : (
                          <>
                            <UserCheck className="w-4 h-4" />
                            Activate
                          </>
                        )}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="mt-6 flex items-center justify-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <span className="px-4 py-2 text-gray-400">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="p-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        )}
      </main>
    </div>
  );
}
