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
import { useAdminAuthStore, adminApi } from '../../stores/adminAuthStore';

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
  const { isAuthenticated, isInitialised } = useAdminAuthStore();
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

  // Redirect if not authenticated
  useEffect(() => {
    if (isInitialised && !isAuthenticated) {
      navigate('/admin/login');
    }
  }, [isAuthenticated, isInitialised, navigate]);

  const fetchStats = async () => {
    try {
      const response = await adminApi.get('/fingerprints/stats');
      setStats(response.data);
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  const fetchFingerprints = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '20',
        min_abuse_score: minAbuseScore.toString(),
        flagged_only: flaggedOnly.toString(),
        sort_by: 'abuse_score',
      });

      const response = await adminApi.get(`/fingerprints?${params}`);
      const data: FingerprintsResponse = response.data;
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
      const response = await adminApi.get(`/fingerprints/${id}`);
      setSelectedFingerprint(response.data);
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
      const endpoint =
        flagModal.action === 'flag'
          ? `/fingerprints/${flagModal.id}/flag`
          : `/fingerprints/${flagModal.id}/unflag`;

      const body =
        flagModal.action === 'flag'
          ? { reason: flagReason, admin_notes: adminNotes || null }
          : { admin_notes: adminNotes || null };

      await adminApi.patch(endpoint, body);

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
    if (isAuthenticated) {
      fetchStats();
    }
  }, [isAuthenticated]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchFingerprints();
    }
  }, [page, minAbuseScore, flaggedOnly, isAuthenticated]);

  const getAbuseScoreBadge = (score: number) => {
    if (score >= 80) return 'bg-red-900/50 text-red-400';
    if (score >= 50) return 'bg-orange-900/50 text-orange-400';
    if (score >= 20) return 'bg-yellow-900/50 text-yellow-400';
    return 'bg-green-900/50 text-green-400';
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-600 rounded-lg">
                <Fingerprint className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Device Fingerprints & Abuse Detection</h1>
                <p className="text-sm text-gray-400">Monitor device fingerprints to detect and prevent abuse</p>
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
        {/* Stats Grid */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-6">
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <p className="text-sm text-gray-400">Total</p>
              <p className="text-2xl font-bold text-white">{stats.total_fingerprints}</p>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <p className="text-sm text-gray-400">Flagged</p>
              <p className="text-2xl font-bold text-red-400">{stats.flagged_count}</p>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <p className="text-sm text-gray-400">High Risk</p>
              <p className="text-2xl font-bold text-orange-400">{stats.high_risk_count}</p>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <p className="text-sm text-gray-400">Multi-User</p>
              <p className="text-2xl font-bold text-yellow-400">{stats.multi_user_count}</p>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <p className="text-sm text-gray-400">Multi-Org</p>
              <p className="text-2xl font-bold text-purple-400">{stats.multi_org_count}</p>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <p className="text-sm text-gray-400">Today</p>
              <p className="text-2xl font-bold text-blue-400">{stats.registrations_today}</p>
            </div>
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <p className="text-sm text-gray-400">This Week</p>
              <p className="text-2xl font-bold text-cyan-400">{stats.registrations_this_week}</p>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 mb-6">
          <div className="flex flex-wrap items-center gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Min Abuse Score
              </label>
              <select
                value={minAbuseScore}
                onChange={(e) => {
                  setMinAbuseScore(Number(e.target.value));
                  setPage(1);
                }}
                className="bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 focus:ring-2 focus:ring-orange-500 focus:border-transparent"
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
                className="h-4 w-4 text-orange-600 bg-gray-700 border-gray-600 rounded focus:ring-orange-500"
              />
              <label htmlFor="flaggedOnly" className="ml-2 text-sm text-gray-300">
                Flagged Only
              </label>
            </div>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded-lg flex items-center gap-2 text-red-200">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <span>{error}</span>
            <button onClick={() => setError('')} className="ml-auto text-red-400 hover:text-red-300">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Table */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
          {loading ? (
            <div className="p-8 text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500 mx-auto"></div>
            </div>
          ) : fingerprints.length === 0 ? (
            <div className="p-8 text-center text-gray-400">No fingerprints found</div>
          ) : (
            <table className="min-w-full divide-y divide-gray-700">
              <thead className="bg-gray-800/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Fingerprint
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Abuse Score
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Users
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Orgs
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    First Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Last Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {fingerprints.map((fp) => (
                  <tr key={fp.id} className={fp.is_flagged ? 'bg-red-900/20' : 'hover:bg-gray-700/50'}>
                    <td className="px-4 py-4">
                      <div className="flex items-center">
                        <code className="text-sm font-mono text-gray-200">
                          {fp.fingerprint_hash}
                        </code>
                        {fp.is_flagged && (
                          <span className="ml-2 px-2 py-0.5 text-xs bg-red-900/50 text-red-400 rounded-full flex items-center">
                            <Flag className="w-3 h-3 mr-1" />
                            Flagged
                          </span>
                        )}
                      </div>
                      {fp.flag_reason && (
                        <p className="text-xs text-red-400 mt-1">{fp.flag_reason}</p>
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
                      <span className="flex items-center text-sm text-gray-300">
                        <Users className="w-4 h-4 mr-1 text-gray-500" />
                        {fp.associated_user_count}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span className="flex items-center text-sm text-gray-300">
                        <Building2 className="w-4 h-4 mr-1 text-gray-500" />
                        {fp.associated_org_count}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-400">
                      {new Date(fp.first_seen_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-400">
                      {new Date(fp.last_seen_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => fetchFingerprintDetail(fp.id)}
                          className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        {fp.is_flagged ? (
                          <button
                            onClick={() => setFlagModal({ id: fp.id, action: 'unflag' })}
                            className="p-1.5 text-green-400 hover:text-green-300 hover:bg-green-900/30 rounded transition-colors"
                            title="Unflag"
                          >
                            <Check className="w-4 h-4" />
                          </button>
                        ) : (
                          <button
                            onClick={() => setFlagModal({ id: fp.id, action: 'flag' })}
                            className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-900/30 rounded transition-colors"
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
            <div className="px-4 py-3 border-t border-gray-700 flex items-center justify-between">
              <p className="text-sm text-gray-400">
                Showing page {page} of {totalPages} ({total} total)
              </p>
              <div className="flex space-x-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="px-3 py-1 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Detail Modal */}
        {selectedFingerprint && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg border border-gray-700 max-w-3xl w-full mx-4 max-h-[80vh] overflow-y-auto">
              <div className="p-6 border-b border-gray-700 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white">Fingerprint Details</h3>
                <button
                  onClick={() => setSelectedFingerprint(null)}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="p-6">
                {detailLoading ? (
                  <div className="text-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500 mx-auto"></div>
                  </div>
                ) : (
                  <>
                    {/* Summary */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div>
                        <p className="text-sm text-gray-400">Abuse Score</p>
                        <p
                          className={`text-xl font-bold ${
                            selectedFingerprint.abuse_score >= 50 ? 'text-red-400' : 'text-white'
                          }`}
                        >
                          {selectedFingerprint.abuse_score}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Users</p>
                        <p className="text-xl font-bold text-white">
                          {selectedFingerprint.associated_user_count}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Organisations</p>
                        <p className="text-xl font-bold text-white">
                          {selectedFingerprint.associated_org_count}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400">Status</p>
                        <p
                          className={`text-xl font-bold ${
                            selectedFingerprint.is_flagged ? 'text-red-400' : 'text-green-400'
                          }`}
                        >
                          {selectedFingerprint.is_flagged ? 'Flagged' : 'Normal'}
                        </p>
                      </div>
                    </div>

                    {selectedFingerprint.flag_reason && (
                      <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg">
                        <p className="text-sm font-medium text-red-400">Flag Reason:</p>
                        <p className="text-sm text-red-300">{selectedFingerprint.flag_reason}</p>
                      </div>
                    )}

                    {selectedFingerprint.admin_notes && (
                      <div className="mb-4 p-3 bg-gray-700/50 border border-gray-600 rounded-lg">
                        <p className="text-sm font-medium text-gray-300">Admin Notes:</p>
                        <p className="text-sm text-gray-400">{selectedFingerprint.admin_notes}</p>
                      </div>
                    )}

                    {/* Associations */}
                    <h4 className="text-md font-semibold text-white mb-3">
                      Associated Accounts ({selectedFingerprint.associations.length})
                    </h4>
                    <div className="space-y-3">
                      {selectedFingerprint.associations.map((assoc) => (
                        <div
                          key={assoc.id}
                          className="p-3 bg-gray-700/50 rounded-lg border border-gray-600"
                        >
                          <div className="flex items-start justify-between">
                            <div>
                              <p className="font-medium text-white">{assoc.user_email}</p>
                              <p className="text-sm text-gray-400">{assoc.user_name}</p>
                            </div>
                            <div className="text-right">
                              <p className="text-sm text-gray-400">
                                Seen {assoc.seen_count} time{assoc.seen_count !== 1 ? 's' : ''}
                              </p>
                            </div>
                          </div>
                          <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-400">
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
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg border border-gray-700 max-w-md w-full mx-4">
              <div className="p-6 border-b border-gray-700">
                <h3 className="text-lg font-semibold text-white">
                  {flagModal.action === 'flag' ? 'Flag Fingerprint' : 'Unflag Fingerprint'}
                </h3>
              </div>
              <div className="p-6 space-y-4">
                {flagModal.action === 'flag' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-1">
                      Reason <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="text"
                      value={flagReason}
                      onChange={(e) => setFlagReason(e.target.value)}
                      className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                      placeholder="e.g., Multiple account abuse"
                    />
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Admin Notes (optional)
                  </label>
                  <textarea
                    value={adminNotes}
                    onChange={(e) => setAdminNotes(e.target.value)}
                    className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                    rows={3}
                    placeholder="Internal notes..."
                  />
                </div>
              </div>
              <div className="p-6 border-t border-gray-700 flex justify-end space-x-3">
                <button
                  onClick={() => {
                    setFlagModal(null);
                    setFlagReason('');
                    setAdminNotes('');
                  }}
                  className="px-4 py-2 border border-gray-600 rounded-lg text-gray-300 hover:bg-gray-700 transition-colors"
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
                  } disabled:opacity-50 disabled:cursor-not-allowed transition-colors`}
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
      </main>
    </div>
  );
}
