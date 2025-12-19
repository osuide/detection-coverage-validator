import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  Search,
  Filter,
  Calendar,
  User,
  Globe,
  CheckCircle,
  XCircle,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  Shield,
  Activity,
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

interface AuditLog {
  id: string;
  admin_id: string;
  admin_email: string;
  admin_role: string;
  action: string;
  ip_address: string;
  user_agent: string | null;
  success: boolean;
  error_message: string | null;
  resource_type: string | null;
  resource_id: string | null;
  timestamp: string;
}

interface AuditLogsResponse {
  logs: AuditLog[];
  total: number;
  page: number;
  per_page: number;
}

const ACTION_COLORS: Record<string, string> = {
  'admin:login': 'bg-green-900/50 text-green-400',
  'admin:logout': 'bg-gray-700 text-gray-300',
  'admin:login_failed': 'bg-red-900/50 text-red-400',
  'admin:login_blocked': 'bg-red-900/50 text-red-400',
  'settings:update': 'bg-blue-900/50 text-blue-400',
  'org:suspend': 'bg-orange-900/50 text-orange-400',
  'org:unsuspend': 'bg-green-900/50 text-green-400',
  'user:suspend': 'bg-orange-900/50 text-orange-400',
  'user:activate': 'bg-green-900/50 text-green-400',
};

export default function AdminAuditLogs() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [actionFilter, setActionFilter] = useState('');
  const [adminFilter, setAdminFilter] = useState('');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('admin_token');
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '50',
      });
      if (actionFilter) params.append('action', actionFilter);
      if (adminFilter) params.append('admin_email', adminFilter);

      const response = await fetch(`${API_BASE_URL}/api/v1/admin/audit-logs?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.status === 401) {
        navigate('/admin/login');
        return;
      }

      if (!response.ok) throw new Error('Failed to fetch audit logs');

      const data: AuditLogsResponse = await response.json();
      setLogs(data.logs);
      setTotal(data.total);
      setTotalPages(Math.ceil(data.total / data.per_page));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, actionFilter]);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  const getActionColor = (action: string) => {
    return ACTION_COLORS[action] || 'bg-gray-700 text-gray-300';
  };

  const formatAction = (action: string) => {
    return action.replace(/_/g, ' ').replace(/:/g, ': ');
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-600 rounded-lg">
                <FileText className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Audit Logs</h1>
                <p className="text-sm text-gray-400">Platform activity and security events</p>
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

        {/* Filters */}
        <div className="mb-6 flex flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setPage(1);
              }}
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-red-500"
            >
              <option value="">All Actions</option>
              <option value="admin:login">Login</option>
              <option value="admin:logout">Logout</option>
              <option value="admin:login_failed">Login Failed</option>
              <option value="settings:update">Settings Update</option>
              <option value="org:suspend">Org Suspend</option>
              <option value="org:unsuspend">Org Unsuspend</option>
            </select>
          </div>

          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              value={adminFilter}
              onChange={(e) => setAdminFilter(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && fetchLogs()}
              placeholder="Filter by admin email..."
              className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>
        </div>

        {/* Stats */}
        <div className="mb-6 flex items-center gap-4 text-sm text-gray-400">
          <span className="flex items-center gap-1">
            <Activity className="w-4 h-4" />
            Total: {total} events
          </span>
          <span>Page {page} of {totalPages}</span>
        </div>

        {/* Logs Table */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          {loading ? (
            <div className="p-8 text-center text-gray-400">
              <div className="animate-spin w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full mx-auto mb-4" />
              Loading audit logs...
            </div>
          ) : logs.length === 0 ? (
            <div className="p-8 text-center text-gray-400">
              <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No audit logs found</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-900/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Timestamp
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Admin
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Action
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      IP Address
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Details
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-sm text-gray-300 whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3 text-gray-500" />
                          {formatDate(log.timestamp)}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 bg-gray-700 rounded-full flex items-center justify-center">
                            <User className="w-4 h-4 text-gray-400" />
                          </div>
                          <div>
                            <div className="text-sm text-white">{log.admin_email}</div>
                            <div className="text-xs text-gray-500 flex items-center gap-1">
                              <Shield className="w-3 h-3" />
                              {log.admin_role}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getActionColor(log.action)}`}
                        >
                          {formatAction(log.action)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {log.success ? (
                          <span className="inline-flex items-center gap-1 text-green-400 text-sm">
                            <CheckCircle className="w-4 h-4" />
                            Success
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-400 text-sm">
                            <XCircle className="w-4 h-4" />
                            Failed
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400">
                        <div className="flex items-center gap-1">
                          <Globe className="w-3 h-3" />
                          {log.ip_address}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm">
                        {log.error_message ? (
                          <span className="text-red-400">{log.error_message}</span>
                        ) : log.resource_type ? (
                          <span className="text-gray-400">
                            {log.resource_type}: {log.resource_id?.slice(0, 8)}...
                          </span>
                        ) : (
                          <span className="text-gray-500">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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
