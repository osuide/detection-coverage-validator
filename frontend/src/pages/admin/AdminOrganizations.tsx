import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Shield, Search, ChevronLeft, ChevronRight,
  Users, Cloud, Scan, AlertTriangle,
  Ban, CheckCircle, ExternalLink
} from 'lucide-react';
import { useAdminAuthStore, adminApi } from '../../stores/adminAuthStore';

interface Organization {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  user_count: number;
  tier: string;
  created_at: string;
  last_activity?: string;
}

interface OrgDetail {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  created_at: string;
  tier: string;
  stripe_customer_id?: string;
  user_count: number;
  cloud_account_count: number;
  scan_count: number;
  detection_count: number;
  owner?: {
    id: string;
    email: string;
    full_name: string;
    role: string;
  };
  members: Array<{
    id: string;
    email: string;
    full_name: string;
    role: string;
    status: string;
    joined_at: string;
  }>;
}

export default function AdminOrganizations() {
  const navigate = useNavigate();
  const { isAuthenticated, isInitialised } = useAdminAuthStore();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<OrgDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [tierFilter, setTierFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const pageSize = 20;

  // Redirect if not authenticated
  useEffect(() => {
    if (isInitialised && !isAuthenticated) {
      navigate('/admin/login');
    }
  }, [isAuthenticated, isInitialised, navigate]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchOrganizations();
    }
  }, [isAuthenticated, page, search, tierFilter, statusFilter]);

  const fetchOrganizations = async () => {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
      });
      if (search) params.set('search', search);
      if (tierFilter) params.set('tier', tierFilter);
      if (statusFilter) params.set('is_active', statusFilter);

      const response = await adminApi.get(`/organizations?${params}`);
      setOrganizations(response.data.items);
      setTotal(response.data.total);
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchOrgDetails = async (orgId: string) => {
    try {
      const response = await adminApi.get(`/organizations/${orgId}`);
      setSelectedOrg(response.data);
    } catch (error) {
      console.error('Failed to fetch org details:', error);
    }
  };

  const suspendOrg = async (orgId: string, reason: string) => {
    setActionLoading(orgId);
    try {
      await adminApi.post(`/organizations/${orgId}/suspend`, { reason });
      fetchOrganizations();
      if (selectedOrg?.id === orgId) {
        fetchOrgDetails(orgId);
      }
    } finally {
      setActionLoading(null);
    }
  };

  const unsuspendOrg = async (orgId: string) => {
    setActionLoading(orgId);
    try {
      await adminApi.post(`/organizations/${orgId}/unsuspend`);
      fetchOrganizations();
      if (selectedOrg?.id === orgId) {
        fetchOrgDetails(orgId);
      }
    } finally {
      setActionLoading(null);
    }
  };

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'enterprise': return 'text-purple-400 bg-purple-400/10';
      case 'subscriber': return 'text-blue-400 bg-blue-400/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Top Nav */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <Link to="/admin/dashboard" className="text-gray-400 hover:text-white">
                <ChevronLeft className="w-5 h-5" />
              </Link>
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-red-600 rounded-lg flex items-center justify-center">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <span className="text-white font-semibold">Organisations</span>
              </div>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex gap-6">
          {/* Organizations List */}
          <div className={`${selectedOrg ? 'w-1/2' : 'w-full'} transition-all`}>
            {/* Filters */}
            <div className="flex gap-4 mb-6">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                  placeholder="Search organisations..."
                  className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-hidden focus:ring-2 focus:ring-red-500"
                />
              </div>
              <select
                value={tierFilter}
                onChange={(e) => { setTierFilter(e.target.value); setPage(1); }}
                className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:ring-2 focus:ring-red-500"
              >
                <option value="">All Tiers</option>
                <option value="free_scan">Free</option>
                <option value="subscriber">Subscriber</option>
                <option value="enterprise">Enterprise</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
                className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:ring-2 focus:ring-red-500"
              >
                <option value="">All Status</option>
                <option value="true">Active</option>
                <option value="false">Suspended</option>
              </select>
            </div>

            {/* Table */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Organisation</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Tier</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Users</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Status</th>
                    <th className="text-right px-4 py-3 text-sm font-medium text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {organizations.map((org) => (
                    <tr
                      key={org.id}
                      onClick={() => fetchOrgDetails(org.id)}
                      className={`border-b border-gray-700 cursor-pointer hover:bg-gray-700/50 transition-colors ${
                        selectedOrg?.id === org.id ? 'bg-gray-700/50' : ''
                      }`}
                    >
                      <td className="px-4 py-3">
                        <div>
                          <p className="text-white font-medium">{org.name}</p>
                          <p className="text-sm text-gray-400">{org.slug}</p>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded-sm text-xs font-medium ${getTierColor(org.tier)}`}>
                          {org.tier}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-300">{org.user_count}</td>
                      <td className="px-4 py-3">
                        {org.is_active ? (
                          <span className="flex items-center gap-1 text-green-400 text-sm">
                            <CheckCircle className="w-4 h-4" /> Active
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-red-400 text-sm">
                            <Ban className="w-4 h-4" /> Suspended
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (org.is_active) {
                              const reason = prompt('Reason for suspension:');
                              if (reason) suspendOrg(org.id, reason);
                            } else {
                              unsuspendOrg(org.id);
                            }
                          }}
                          disabled={actionLoading === org.id}
                          className={`px-3 py-1 rounded text-sm ${
                            org.is_active
                              ? 'text-red-400 hover:bg-red-400/10'
                              : 'text-green-400 hover:bg-green-400/10'
                          }`}
                        >
                          {actionLoading === org.id ? '...' : org.is_active ? 'Suspend' : 'Unsuspend'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {organizations.length === 0 && (
                <div className="text-center py-8 text-gray-400">
                  No organisations found
                </div>
              )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4">
                <p className="text-sm text-gray-400">
                  Showing {((page - 1) * pageSize) + 1} - {Math.min(page * pageSize, total)} of {total}
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="p-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-white disabled:opacity-50"
                  >
                    <ChevronLeft className="w-5 h-5" />
                  </button>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="p-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-white disabled:opacity-50"
                  >
                    <ChevronRight className="w-5 h-5" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Organization Details Panel */}
          {selectedOrg && (
            <div className="w-1/2 bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h2 className="text-xl font-semibold text-white">{selectedOrg.name}</h2>
                  <p className="text-gray-400">{selectedOrg.slug}</p>
                </div>
                <button
                  onClick={() => setSelectedOrg(null)}
                  className="text-gray-400 hover:text-white"
                >
                  &times;
                </button>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="p-4 bg-gray-700/50 rounded-lg">
                  <div className="flex items-center gap-2 text-gray-400 mb-1">
                    <Users className="w-4 h-4" />
                    <span className="text-sm">Users</span>
                  </div>
                  <p className="text-2xl font-bold text-white">{selectedOrg.user_count}</p>
                </div>
                <div className="p-4 bg-gray-700/50 rounded-lg">
                  <div className="flex items-center gap-2 text-gray-400 mb-1">
                    <Cloud className="w-4 h-4" />
                    <span className="text-sm">Cloud Accounts</span>
                  </div>
                  <p className="text-2xl font-bold text-white">{selectedOrg.cloud_account_count}</p>
                </div>
                <div className="p-4 bg-gray-700/50 rounded-lg">
                  <div className="flex items-center gap-2 text-gray-400 mb-1">
                    <Scan className="w-4 h-4" />
                    <span className="text-sm">Scans</span>
                  </div>
                  <p className="text-2xl font-bold text-white">{selectedOrg.scan_count}</p>
                </div>
                <div className="p-4 bg-gray-700/50 rounded-lg">
                  <div className="flex items-center gap-2 text-gray-400 mb-1">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-sm">Detections</span>
                  </div>
                  <p className="text-2xl font-bold text-white">{selectedOrg.detection_count}</p>
                </div>
              </div>

              {/* Subscription */}
              <div className="mb-6">
                <h3 className="text-sm font-medium text-gray-400 mb-2">Subscription</h3>
                <div className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg">
                  <span className={`px-2 py-1 rounded-sm text-sm font-medium ${getTierColor(selectedOrg.tier)}`}>
                    {selectedOrg.tier}
                  </span>
                  {selectedOrg.stripe_customer_id && (
                    <a
                      href={`https://dashboard.stripe.com/customers/${selectedOrg.stripe_customer_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300"
                    >
                      View in Stripe <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              </div>

              {/* Owner */}
              {selectedOrg.owner && (
                <div className="mb-6">
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Owner</h3>
                  <div className="p-3 bg-gray-700/50 rounded-lg">
                    <p className="text-white">{selectedOrg.owner.full_name || 'No name'}</p>
                    <p className="text-sm text-gray-400">{selectedOrg.owner.email}</p>
                  </div>
                </div>
              )}

              {/* Members */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">
                  Members ({selectedOrg.members.length})
                </h3>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {selectedOrg.members.map((member) => (
                    <div key={member.id} className="flex items-center justify-between p-2 bg-gray-700/50 rounded-lg">
                      <div>
                        <p className="text-sm text-white">{member.full_name || member.email}</p>
                        <p className="text-xs text-gray-400">{member.email}</p>
                      </div>
                      <span className="text-xs text-gray-400">{member.role}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
