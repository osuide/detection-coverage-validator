import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield, Users, Building2, CreditCard, Activity,
  AlertTriangle, Settings, LogOut, TrendingUp,
  Server, Database, Clock, ChevronRight, FileText, UserCog
} from 'lucide-react';

interface SystemHealth {
  status: string;
  api_latency_ms: number;
  error_rate_percent: number;
  active_scans: number;
  queue_depth: number;
  database_connections: number;
  cache_hit_rate: number;
}

interface BusinessMetrics {
  total_organizations: number;
  active_organizations: number;
  trial_organizations: number;
  churned_30d: number;
  total_users: number;
  active_users_7d: number;
  mrr_cents: number;
  arr_cents: number;
  tier_breakdown: Record<string, number>;
}

interface UsageMetrics {
  scans_24h: number;
  scans_7d: number;
  scans_30d: number;
  detections_discovered: number;
  techniques_mapped: number;
  cloud_accounts_total: number;
  cloud_accounts_aws: number;
  cloud_accounts_gcp: number;
}

interface SecurityMetrics {
  failed_logins_24h: number;
  locked_accounts: number;
  mfa_enabled_percent: number;
  suspicious_activity_count: number;
}

interface AdminProfile {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  mfa_enabled: boolean;
  permissions: string[];
}

export default function AdminDashboard() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState<AdminProfile | null>(null);
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [businessMetrics, setBusinessMetrics] = useState<BusinessMetrics | null>(null);
  const [usageMetrics, setUsageMetrics] = useState<UsageMetrics | null>(null);
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const adminToken = localStorage.getItem('admin_token');

  useEffect(() => {
    if (!adminToken) {
      navigate('/admin/login');
      return;
    }

    const fetchData = async () => {
      try {
        const headers = { Authorization: `Bearer ${adminToken}` };

        const [profileRes, systemRes, businessRes, usageRes, securityRes] = await Promise.all([
          fetch('/api/v1/admin/auth/me', { headers }),
          fetch('/api/v1/admin/metrics/system', { headers }),
          fetch('/api/v1/admin/metrics/business', { headers }),
          fetch('/api/v1/admin/metrics/usage', { headers }),
          fetch('/api/v1/admin/metrics/security', { headers }),
        ]);

        if (!profileRes.ok) {
          localStorage.removeItem('admin_token');
          navigate('/admin/login');
          return;
        }

        setProfile(await profileRes.json());
        if (systemRes.ok) setSystemHealth(await systemRes.json());
        if (businessRes.ok) setBusinessMetrics(await businessRes.json());
        if (usageRes.ok) setUsageMetrics(await usageRes.json());
        if (securityRes.ok) setSecurityMetrics(await securityRes.json());
      } catch (error) {
        console.error('Failed to fetch admin data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [adminToken, navigate]);

  const handleLogout = async () => {
    try {
      await fetch('/api/v1/admin/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}` },
      });
    } finally {
      localStorage.removeItem('admin_token');
      localStorage.removeItem('admin_refresh_token');
      navigate('/admin/login');
    }
  };

  const formatCurrency = (cents: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(cents / 100);
  };

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
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-red-600 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="text-white font-semibold">Admin Portal</span>
            </div>

            <div className="flex items-center gap-4">
              <span className="text-sm text-gray-400">
                {profile?.email} ({profile?.role.replace('_', ' ')})
              </span>
              <button
                onClick={handleLogout}
                className="p-2 text-gray-400 hover:text-white transition-colors"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* System Status */}
        {systemHealth && (
          <div className="mb-8 p-4 bg-gray-800 rounded-xl border border-gray-700">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${systemHealth.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                <span className="text-white font-medium">System Status: {systemHealth.status}</span>
              </div>
              <div className="flex items-center gap-6 text-sm">
                <div className="flex items-center gap-2 text-gray-400">
                  <Clock className="w-4 h-4" />
                  <span>{systemHealth.api_latency_ms}ms latency</span>
                </div>
                <div className="flex items-center gap-2 text-gray-400">
                  <Activity className="w-4 h-4" />
                  <span>{systemHealth.active_scans} active scans</span>
                </div>
                <div className="flex items-center gap-2 text-gray-400">
                  <Database className="w-4 h-4" />
                  <span>{systemHealth.database_connections} DB connections</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <Link
            to="/admin/organizations"
            className="p-4 bg-gray-800 rounded-xl border border-gray-700 hover:border-gray-600 transition-colors group"
          >
            <Building2 className="w-6 h-6 text-blue-400 mb-2" />
            <h3 className="text-white font-medium">Organizations</h3>
            <p className="text-sm text-gray-400">Manage customers</p>
          </Link>

          <Link
            to="/admin/users"
            className="p-4 bg-gray-800 rounded-xl border border-gray-700 hover:border-gray-600 transition-colors group"
          >
            <Users className="w-6 h-6 text-green-400 mb-2" />
            <h3 className="text-white font-medium">Users</h3>
            <p className="text-sm text-gray-400">User management</p>
          </Link>

          <Link
            to="/admin/billing"
            className="p-4 bg-gray-800 rounded-xl border border-gray-700 hover:border-gray-600 transition-colors group"
          >
            <CreditCard className="w-6 h-6 text-purple-400 mb-2" />
            <h3 className="text-white font-medium">Billing</h3>
            <p className="text-sm text-gray-400">Revenue & subscriptions</p>
          </Link>

          <Link
            to="/admin/settings"
            className="p-4 bg-gray-800 rounded-xl border border-gray-700 hover:border-gray-600 transition-colors group"
          >
            <Settings className="w-6 h-6 text-gray-400 mb-2" />
            <h3 className="text-white font-medium">Settings</h3>
            <p className="text-sm text-gray-400">Platform config</p>
          </Link>

          <Link
            to="/admin/audit-logs"
            className="p-4 bg-gray-800 rounded-xl border border-gray-700 hover:border-gray-600 transition-colors group"
          >
            <FileText className="w-6 h-6 text-yellow-400 mb-2" />
            <h3 className="text-white font-medium">Audit Logs</h3>
            <p className="text-sm text-gray-400">Activity history</p>
          </Link>

          <Link
            to="/admin/admins"
            className="p-4 bg-gray-800 rounded-xl border border-gray-700 hover:border-gray-600 transition-colors group"
          >
            <UserCog className="w-6 h-6 text-red-400 mb-2" />
            <h3 className="text-white font-medium">Admins</h3>
            <p className="text-sm text-gray-400">Manage admin users</p>
          </Link>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Business Metrics */}
          {businessMetrics && (
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-white">Business Metrics</h2>
                <TrendingUp className="w-5 h-5 text-green-400" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-2xl font-bold text-white">{formatCurrency(businessMetrics.mrr_cents)}</p>
                  <p className="text-sm text-gray-400">Monthly Revenue</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{formatCurrency(businessMetrics.arr_cents)}</p>
                  <p className="text-sm text-gray-400">Annual Revenue</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{businessMetrics.total_organizations}</p>
                  <p className="text-sm text-gray-400">Total Organizations</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{businessMetrics.active_users_7d}</p>
                  <p className="text-sm text-gray-400">Active Users (7d)</p>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-700">
                <p className="text-sm text-gray-400 mb-2">Subscription Tiers</p>
                <div className="flex gap-2">
                  {Object.entries(businessMetrics.tier_breakdown).map(([tier, count]) => (
                    <span key={tier} className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300">
                      {tier}: {count}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Usage Metrics */}
          {usageMetrics && (
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-white">Platform Usage</h2>
                <Server className="w-5 h-5 text-blue-400" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-2xl font-bold text-white">{usageMetrics.scans_24h}</p>
                  <p className="text-sm text-gray-400">Scans (24h)</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{usageMetrics.scans_7d}</p>
                  <p className="text-sm text-gray-400">Scans (7d)</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{usageMetrics.detections_discovered.toLocaleString()}</p>
                  <p className="text-sm text-gray-400">Detections Found</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{usageMetrics.techniques_mapped}</p>
                  <p className="text-sm text-gray-400">Techniques Mapped</p>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-700">
                <p className="text-sm text-gray-400 mb-2">Cloud Accounts</p>
                <div className="flex gap-4">
                  <span className="text-sm text-gray-300">
                    AWS: <span className="text-white font-medium">{usageMetrics.cloud_accounts_aws}</span>
                  </span>
                  <span className="text-sm text-gray-300">
                    GCP: <span className="text-white font-medium">{usageMetrics.cloud_accounts_gcp}</span>
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Security Metrics */}
        {securityMetrics && (
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Security Overview</h2>
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              <div>
                <p className={`text-2xl font-bold ${securityMetrics.failed_logins_24h > 10 ? 'text-red-400' : 'text-white'}`}>
                  {securityMetrics.failed_logins_24h}
                </p>
                <p className="text-sm text-gray-400">Failed Logins (24h)</p>
              </div>
              <div>
                <p className={`text-2xl font-bold ${securityMetrics.locked_accounts > 0 ? 'text-yellow-400' : 'text-white'}`}>
                  {securityMetrics.locked_accounts}
                </p>
                <p className="text-sm text-gray-400">Locked Accounts</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{securityMetrics.mfa_enabled_percent}%</p>
                <p className="text-sm text-gray-400">MFA Adoption</p>
              </div>
              <div>
                <p className={`text-2xl font-bold ${securityMetrics.suspicious_activity_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                  {securityMetrics.suspicious_activity_count}
                </p>
                <p className="text-sm text-gray-400">Security Incidents</p>
              </div>
            </div>

            {securityMetrics.suspicious_activity_count > 0 && (
              <Link
                to="/admin/security-incidents"
                className="mt-4 flex items-center gap-2 text-red-400 hover:text-red-300 text-sm"
              >
                View security incidents
                <ChevronRight className="w-4 h-4" />
              </Link>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
