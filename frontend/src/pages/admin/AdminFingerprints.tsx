import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Fingerprint,
  Flag,
  ChevronLeft,
  ChevronRight,
  Users,
  Building2,
  Calendar,
  Globe,
  Eye,
  X,
  Check,
  AlertCircle,
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

interface FingerprintData {
  id: string;
  fingerprint_hash: string;
  abuse_score: number;
  is_flagged: boolean;
  flag_reason: string | null;
  associated_user_count: number;
  associated_org_count: number;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
}

interface Association {
  id: string;
  user_id: string;
  user_email: string;
  user_name: string;
  organization_id: string | null;
  organization_name: string | null;
  ip_address: string | null;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
}

interface FingerprintDetail extends FingerprintData {
  admin_notes: string | null;
  associations: Association[];
}

interface FingerprintsResponse {
  fingerprints: FingerprintData[];
  total: number;
  page: number;
  per_page: number;
}

interface Stats {
  total_fingerprints: number;
  flagged_count: number;
  high_risk_count: number;
  multi_user_count: number;
  multi_org_count: number;
  registrations_today: number;
  registrations_this_week: number;
}

export default function AdminFingerprints() {
  const navigate = useNavigate();
  const [fingerprints, setFingerprints] = useState<FingerprintData[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [minAbuseScore, setMinAbuseScore] = useState(0);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [selectedFingerprint, setSelectedFingerprint] = useState<FingerprintDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [flagModal, setFlagModal] = useState<{ id: string; action: 'flag' | 'unflag' } | null>(null);
  const [flagReason, setFlagReason] = useState('');
  const [adminNotes, setAdminNotes] = useState('');

  const fetchStats = async () => {
    try {
      const token = localStorage.getItem('admin_token');
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/fingerprints/stats`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  const fetchFingerprints = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('admin_token');
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '20',
        min_abuse_score: minAbuseScore.toString(),
        flagged_only: flaggedOnly.toString(),
        sort_by: 'abuse_score',
      });

      const response = await fetch(`${API_BASE_URL}/api/v1/admin/fingerprints?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.status === 401) {
        navigate('/admin/login');
        return;
      }

      if (!response.ok) throw new Error('Failed to fetch fingerprints');

      const data: FingerprintsResponse = await response.json();
      setFingerprints(data.fingerprints);
      setTotal(data.total);
      setTotalPages(Math.ceil(data.total / data.per_page));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load fingerprints');
    } finally {
      setLoading(false);
    }
  };

  const fetchFingerprintDetail = async (id: string) => {
    setDetailLoading(true);
    try {
      const token = localStorage.getItem('admin_token');
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/fingerprints/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) throw new Error('Failed to fetch fingerprint details');

      const data: FingerprintDetail = await response.json();
      setSelectedFingerprint(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load details');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleFlagAction = async () => {
    if (!flagModal) return;
    setActionLoading(flagModal.id);

    try {
      const token = localStorage.getItem('admin_token');
      const endpoint =
        flagModal.action === 'flag'
          ? `${API_BASE_URL}/api/v1/admin/fingerprints/${flagModal.id}/flag`
          : `${API_BASE_URL}/api/v1/admin/fingerprints/${flagModal.id}/unflag`;

      const body =
        flagModal.action === 'flag'
          ? { reason: flagReason, admin_notes: adminNotes || null }
          : { admin_notes: adminNotes || null };

      const response = await fetch(endpoint, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) throw new Error('Failed to update fingerprint');

      // Refresh data
      fetchFingerprints();
      fetchStats();
      setFlagModal(null);
      setFlagReason('');
      setAdminNotes('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed');
    } finally {
      setActionLoading(null);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    fetchFingerprints();
  }, [page, minAbuseScore, flaggedOnly]);

  const getAbuseScoreBadge = (score: number) => {
    if (score >= 80) return 'bg-red-100 text-red-800';
    if (score >= 50) return 'bg-orange-100 text-orange-800';
    if (score >= 20) return 'bg-yellow-100 text-yellow-800';
    return 'bg-green-100 text-green-800';
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900 flex items-center">
            <Fingerprint className="w-7 h-7 mr-3 text-purple-600" />
            Device Fingerprints & Abuse Detection
          </h1>
          <p className="text-gray-600 mt-1">
            Monitor device fingerprints to detect and prevent abuse
          </p>
        </div>

        {/* Stats Grid */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-6">
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-500">Total</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total_fingerprints}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-500">Flagged</p>
              <p className="text-2xl font-bold text-red-600">{stats.flagged_count}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-500">High Risk</p>
              <p className="text-2xl font-bold text-orange-600">{stats.high_risk_count}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-500">Multi-User</p>
              <p className="text-2xl font-bold text-yellow-600">{stats.multi_user_count}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-500">Multi-Org</p>
              <p className="text-2xl font-bold text-purple-600">{stats.multi_org_count}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-500">Today</p>
              <p className="text-2xl font-bold text-blue-600">{stats.registrations_today}</p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-500">This Week</p>
              <p className="text-2xl font-bold text-cyan-600">{stats.registrations_this_week}</p>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="bg-white rounded-lg shadow p-4 mb-6">
          <div className="flex flex-wrap items-center gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Min Abuse Score
              </label>
              <select
                value={minAbuseScore}
                onChange={(e) => {
                  setMinAbuseScore(Number(e.target.value));
                  setPage(1);
                }}
                className="border border-gray-300 rounded-lg px-3 py-2"
              >
                <option value={0}>All</option>
                <option value={20}>20+</option>
                <option value={50}>50+ (High Risk)</option>
                <option value={80}>80+ (Critical)</option>
              </select>
            </div>
            <div className="flex items-center">
              <input
                type="checkbox"
                id="flaggedOnly"
                checked={flaggedOnly}
                onChange={(e) => {
                  setFlaggedOnly(e.target.checked);
                  setPage(1);
                }}
                className="h-4 w-4 text-purple-600 rounded border-gray-300"
              />
              <label htmlFor="flaggedOnly" className="ml-2 text-sm text-gray-700">
                Flagged Only
              </label>
            </div>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center">
            <AlertCircle className="w-5 h-5 text-red-600 mr-2" />
            <span className="text-red-700">{error}</span>
            <button onClick={() => setError('')} className="ml-auto text-red-600">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Table */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {loading ? (
            <div className="p-8 text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto"></div>
            </div>
          ) : fingerprints.length === 0 ? (
            <div className="p-8 text-center text-gray-500">No fingerprints found</div>
          ) : (
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Fingerprint
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Abuse Score
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Users
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Orgs
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    First Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Last Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {fingerprints.map((fp) => (
                  <tr key={fp.id} className={fp.is_flagged ? 'bg-red-50' : ''}>
                    <td className="px-4 py-4">
                      <div className="flex items-center">
                        <code className="text-sm font-mono text-gray-900">
                          {fp.fingerprint_hash}
                        </code>
                        {fp.is_flagged && (
                          <span className="ml-2 px-2 py-0.5 text-xs bg-red-100 text-red-800 rounded-full flex items-center">
                            <Flag className="w-3 h-3 mr-1" />
                            Flagged
                          </span>
                        )}
                      </div>
                      {fp.flag_reason && (
                        <p className="text-xs text-red-600 mt-1">{fp.flag_reason}</p>
                      )}
                    </td>
                    <td className="px-4 py-4">
                      <span
                        className={`px-2 py-1 text-sm font-medium rounded-full ${getAbuseScoreBadge(fp.abuse_score)}`}
                      >
                        {fp.abuse_score}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span className="flex items-center text-sm text-gray-900">
                        <Users className="w-4 h-4 mr-1 text-gray-400" />
                        {fp.associated_user_count}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span className="flex items-center text-sm text-gray-900">
                        <Building2 className="w-4 h-4 mr-1 text-gray-400" />
                        {fp.associated_org_count}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-500">
                      {new Date(fp.first_seen_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-500">
                      {new Date(fp.last_seen_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => fetchFingerprintDetail(fp.id)}
                          className="p-1 text-gray-600 hover:bg-gray-100 rounded"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        {fp.is_flagged ? (
                          <button
                            onClick={() => setFlagModal({ id: fp.id, action: 'unflag' })}
                            className="p-1 text-green-600 hover:bg-green-50 rounded"
                            title="Unflag"
                          >
                            <Check className="w-4 h-4" />
                          </button>
                        ) : (
                          <button
                            onClick={() => setFlagModal({ id: fp.id, action: 'flag' })}
                            className="p-1 text-red-600 hover:bg-red-50 rounded"
                            title="Flag as Abusive"
                          >
                            <Flag className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="px-4 py-3 border-t border-gray-200 flex items-center justify-between">
              <p className="text-sm text-gray-700">
                Showing page {page} of {totalPages} ({total} total)
              </p>
              <div className="flex space-x-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 border rounded-lg disabled:opacity-50"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="px-3 py-1 border rounded-lg disabled:opacity-50"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Detail Modal */}
        {selectedFingerprint && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg shadow-xl max-w-3xl w-full mx-4 max-h-[80vh] overflow-y-auto">
              <div className="p-6 border-b border-gray-200 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-900">Fingerprint Details</h3>
                <button
                  onClick={() => setSelectedFingerprint(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="p-6">
                {detailLoading ? (
                  <div className="text-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto"></div>
                  </div>
                ) : (
                  <>
                    {/* Summary */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div>
                        <p className="text-sm text-gray-500">Abuse Score</p>
                        <p
                          className={`text-xl font-bold ${
                            selectedFingerprint.abuse_score >= 50 ? 'text-red-600' : 'text-gray-900'
                          }`}
                        >
                          {selectedFingerprint.abuse_score}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Users</p>
                        <p className="text-xl font-bold text-gray-900">
                          {selectedFingerprint.associated_user_count}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Organisations</p>
                        <p className="text-xl font-bold text-gray-900">
                          {selectedFingerprint.associated_org_count}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Status</p>
                        <p
                          className={`text-xl font-bold ${
                            selectedFingerprint.is_flagged ? 'text-red-600' : 'text-green-600'
                          }`}
                        >
                          {selectedFingerprint.is_flagged ? 'Flagged' : 'Normal'}
                        </p>
                      </div>
                    </div>

                    {selectedFingerprint.flag_reason && (
                      <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                        <p className="text-sm font-medium text-red-800">Flag Reason:</p>
                        <p className="text-sm text-red-700">{selectedFingerprint.flag_reason}</p>
                      </div>
                    )}

                    {selectedFingerprint.admin_notes && (
                      <div className="mb-4 p-3 bg-gray-50 border border-gray-200 rounded-lg">
                        <p className="text-sm font-medium text-gray-800">Admin Notes:</p>
                        <p className="text-sm text-gray-700">{selectedFingerprint.admin_notes}</p>
                      </div>
                    )}

                    {/* Associations */}
                    <h4 className="text-md font-semibold text-gray-900 mb-3">
                      Associated Accounts ({selectedFingerprint.associations.length})
                    </h4>
                    <div className="space-y-3">
                      {selectedFingerprint.associations.map((assoc) => (
                        <div
                          key={assoc.id}
                          className="p-3 bg-gray-50 rounded-lg border border-gray-200"
                        >
                          <div className="flex items-start justify-between">
                            <div>
                              <p className="font-medium text-gray-900">{assoc.user_email}</p>
                              <p className="text-sm text-gray-600">{assoc.user_name}</p>
                            </div>
                            <div className="text-right">
                              <p className="text-sm text-gray-500">
                                Seen {assoc.seen_count} time{assoc.seen_count !== 1 ? 's' : ''}
                              </p>
                            </div>
                          </div>
                          <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-500">
                            {assoc.organization_name && (
                              <span className="flex items-center">
                                <Building2 className="w-3 h-3 mr-1" />
                                {assoc.organization_name}
                              </span>
                            )}
                            {assoc.ip_address && (
                              <span className="flex items-center">
                                <Globe className="w-3 h-3 mr-1" />
                                {assoc.ip_address}
                              </span>
                            )}
                            <span className="flex items-center">
                              <Calendar className="w-3 h-3 mr-1" />
                              First: {new Date(assoc.first_seen_at).toLocaleDateString()}
                            </span>
                            <span className="flex items-center">
                              <Calendar className="w-3 h-3 mr-1" />
                              Last: {new Date(assoc.last_seen_at).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Flag/Unflag Modal */}
        {flagModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
              <div className="p-6 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">
                  {flagModal.action === 'flag' ? 'Flag Fingerprint' : 'Unflag Fingerprint'}
                </h3>
              </div>
              <div className="p-6 space-y-4">
                {flagModal.action === 'flag' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Reason <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      value={flagReason}
                      onChange={(e) => setFlagReason(e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2"
                      placeholder="e.g., Multiple account abuse"
                    />
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Admin Notes (optional)
                  </label>
                  <textarea
                    value={adminNotes}
                    onChange={(e) => setAdminNotes(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2"
                    rows={3}
                    placeholder="Internal notes..."
                  />
                </div>
              </div>
              <div className="p-6 border-t border-gray-200 flex justify-end space-x-3">
                <button
                  onClick={() => {
                    setFlagModal(null);
                    setFlagReason('');
                    setAdminNotes('');
                  }}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleFlagAction}
                  disabled={
                    actionLoading === flagModal.id ||
                    (flagModal.action === 'flag' && !flagReason.trim())
                  }
                  className={`px-4 py-2 rounded-lg text-white ${
                    flagModal.action === 'flag'
                      ? 'bg-red-600 hover:bg-red-700'
                      : 'bg-green-600 hover:bg-green-700'
                  } disabled:opacity-50`}
                >
                  {actionLoading === flagModal.id
                    ? 'Processing...'
                    : flagModal.action === 'flag'
                      ? 'Flag'
                      : 'Unflag'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
