import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  CreditCard,
  DollarSign,
  TrendingUp,
  Building2,
  Users,
  Calendar,
  AlertCircle,
  CheckCircle,
  XCircle,
  ExternalLink,
  RefreshCw,
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

interface BillingStats {
  total_revenue: number;
  mrr: number;
  active_subscriptions: number;
  trial_subscriptions: number;
  churned_this_month: number;
  new_this_month: number;
}

interface Subscription {
  id: string;
  organization_id: string;
  organization_name: string;
  plan: string;
  status: 'active' | 'past_due' | 'canceled' | 'trialing';
  current_period_end: string;
  amount: number;
  created_at: string;
}

export default function AdminBilling() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<BillingStats | null>(null);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchBillingData = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('admin_token');

      const [statsRes, subsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/v1/admin/billing/stats`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch(`${API_BASE_URL}/api/v1/admin/billing/subscriptions?limit=20`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      ]);

      if (statsRes.status === 401 || subsRes.status === 401) {
        navigate('/admin/login');
        return;
      }

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      if (subsRes.ok) {
        const subsData = await subsRes.json();
        setSubscriptions(subsData.subscriptions || []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load billing data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBillingData();
  }, []);

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(amount);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-green-900/50 text-green-400">
            <CheckCircle className="w-3 h-3" />
            Active
          </span>
        );
      case 'trialing':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-blue-900/50 text-blue-400">
            <RefreshCw className="w-3 h-3" />
            Trial
          </span>
        );
      case 'past_due':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-orange-900/50 text-orange-400">
            <AlertCircle className="w-3 h-3" />
            Past Due
          </span>
        );
      case 'canceled':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-red-900/50 text-red-400">
            <XCircle className="w-3 h-3" />
            Canceled
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-700 text-gray-300">
            {status}
          </span>
        );
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin w-12 h-12 border-4 border-red-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-gray-400">Loading billing data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-600 rounded-lg">
                <CreditCard className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Billing Overview</h1>
                <p className="text-sm text-gray-400">Revenue and subscriptions</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <a
                href="https://dashboard.stripe.com"
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors flex items-center gap-2"
              >
                <ExternalLink className="w-4 h-4" />
                Stripe Dashboard
              </a>
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
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-green-900/50 rounded-lg">
                <DollarSign className="w-6 h-6 text-green-400" />
              </div>
              <span className="text-xs text-gray-500">This Month</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">
              {stats ? formatCurrency(stats.total_revenue) : '$0.00'}
            </div>
            <p className="text-sm text-gray-400">Total Revenue</p>
          </div>

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-blue-900/50 rounded-lg">
                <TrendingUp className="w-6 h-6 text-blue-400" />
              </div>
              <span className="text-xs text-gray-500">Monthly</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">
              {stats ? formatCurrency(stats.mrr) : '$0.00'}
            </div>
            <p className="text-sm text-gray-400">MRR</p>
          </div>

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-purple-900/50 rounded-lg">
                <Users className="w-6 h-6 text-purple-400" />
              </div>
            </div>
            <div className="text-2xl font-bold text-white mb-1">
              {stats?.active_subscriptions || 0}
            </div>
            <p className="text-sm text-gray-400">Active Subscriptions</p>
          </div>

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-orange-900/50 rounded-lg">
                <RefreshCw className="w-6 h-6 text-orange-400" />
              </div>
            </div>
            <div className="text-2xl font-bold text-white mb-1">
              {stats?.trial_subscriptions || 0}
            </div>
            <p className="text-sm text-gray-400">Active Trials</p>
          </div>
        </div>

        {/* Growth Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <h3 className="text-lg font-medium text-white mb-4">This Month</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-gray-400">New Subscriptions</span>
                <span className="text-green-400 font-medium">
                  +{stats?.new_this_month || 0}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Churned</span>
                <span className="text-red-400 font-medium">
                  -{stats?.churned_this_month || 0}
                </span>
              </div>
              <div className="flex items-center justify-between pt-4 border-t border-gray-700">
                <span className="text-gray-300 font-medium">Net Change</span>
                <span
                  className={`font-medium ${
                    (stats?.new_this_month || 0) - (stats?.churned_this_month || 0) >= 0
                      ? 'text-green-400'
                      : 'text-red-400'
                  }`}
                >
                  {(stats?.new_this_month || 0) - (stats?.churned_this_month || 0)}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <h3 className="text-lg font-medium text-white mb-4">Quick Actions</h3>
            <div className="space-y-3">
              <a
                href="https://dashboard.stripe.com/invoices"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between p-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
              >
                <span className="text-gray-300">View All Invoices</span>
                <ExternalLink className="w-4 h-4 text-gray-400" />
              </a>
              <a
                href="https://dashboard.stripe.com/customers"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between p-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
              >
                <span className="text-gray-300">Manage Customers</span>
                <ExternalLink className="w-4 h-4 text-gray-400" />
              </a>
              <a
                href="https://dashboard.stripe.com/subscriptions"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between p-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
              >
                <span className="text-gray-300">All Subscriptions</span>
                <ExternalLink className="w-4 h-4 text-gray-400" />
              </a>
            </div>
          </div>
        </div>

        {/* Recent Subscriptions */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700">
            <h3 className="text-lg font-medium text-white">Recent Subscriptions</h3>
          </div>

          {subscriptions.length === 0 ? (
            <div className="p-8 text-center text-gray-400">
              <CreditCard className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No subscriptions yet</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-900/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Organization
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Plan
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Amount
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Renews
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {subscriptions.map((sub) => (
                  <tr key={sub.id} className="hover:bg-gray-700/50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <Building2 className="w-4 h-4 text-gray-500" />
                        <span className="text-white">{sub.organization_name}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-gray-300 capitalize">{sub.plan}</span>
                    </td>
                    <td className="px-6 py-4">{getStatusBadge(sub.status)}</td>
                    <td className="px-6 py-4 text-white font-medium">
                      {formatCurrency(sub.amount)}/mo
                    </td>
                    <td className="px-6 py-4 text-gray-400">
                      <div className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {formatDate(sub.current_period_end)}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </main>
    </div>
  );
}
