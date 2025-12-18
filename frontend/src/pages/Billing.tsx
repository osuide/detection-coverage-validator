import { useState, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { billingApi, Subscription, Pricing, Invoice } from '../services/billingApi'

export default function Billing() {
  const { token, user } = useAuth()
  const [subscription, setSubscription] = useState<Subscription | null>(null)
  const [pricing, setPricing] = useState<Pricing | null>(null)
  const [invoices, setInvoices] = useState<Invoice[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [checkoutLoading, setCheckoutLoading] = useState(false)
  const [portalLoading, setPortalLoading] = useState(false)
  const [additionalAccounts, setAdditionalAccounts] = useState(0)

  useEffect(() => {
    if (token) {
      loadData()
    }
  }, [token])

  const loadData = async () => {
    if (!token) return
    setLoading(true)
    setError(null)

    try {
      const [subData, pricingData, invoicesData] = await Promise.all([
        billingApi.getSubscription(token),
        billingApi.getPricing(token),
        billingApi.getInvoices(token),
      ])
      setSubscription(subData)
      setPricing(pricingData)
      setInvoices(invoicesData)
    } catch (err) {
      console.error('Failed to load billing data:', err)
      setError('Failed to load billing information')
    } finally {
      setLoading(false)
    }
  }

  const handleSubscribe = async () => {
    if (!token) return
    setCheckoutLoading(true)
    setError(null)

    try {
      const result = await billingApi.createCheckout(
        token,
        `${window.location.origin}/settings/billing?success=true`,
        `${window.location.origin}/settings/billing?canceled=true`,
        additionalAccounts
      )
      window.location.href = result.checkout_url
    } catch (err: any) {
      console.error('Failed to create checkout:', err)
      if (err.response?.status === 503) {
        setError('Stripe billing is not configured. Please contact support.')
      } else {
        setError('Failed to start checkout. Please try again.')
      }
      setCheckoutLoading(false)
    }
  }

  const handleManageBilling = async () => {
    if (!token) return
    setPortalLoading(true)
    setError(null)

    try {
      const result = await billingApi.createPortal(
        token,
        `${window.location.origin}/settings/billing`
      )
      window.location.href = result.portal_url
    } catch (err: any) {
      console.error('Failed to create portal:', err)
      if (err.response?.status === 400) {
        setError('No active subscription to manage.')
      } else {
        setError('Failed to open billing portal. Please try again.')
      }
      setPortalLoading(false)
    }
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const formatCurrency = (cents: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(cents / 100)
  }

  const getTierBadgeColor = (tier: string) => {
    switch (tier) {
      case 'subscriber':
        return 'bg-blue-100 text-blue-800'
      case 'enterprise':
        return 'bg-purple-100 text-purple-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  const getStatusBadgeColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800'
      case 'past_due':
        return 'bg-yellow-100 text-yellow-800'
      case 'canceled':
        return 'bg-red-100 text-red-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  // Check URL params for success/canceled
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.get('success') === 'true') {
      // Clear the URL params
      window.history.replaceState({}, '', window.location.pathname)
      // Reload data to get updated subscription
      loadData()
    } else if (params.get('canceled') === 'true') {
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  const isFreeTier = subscription?.tier === 'free_scan'
  const isOwner = user?.role === 'owner'

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-gray-900">Billing & Subscription</h1>
        <p className="mt-1 text-sm text-gray-600">
          Manage your subscription and billing details
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* Current Plan */}
      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Current Plan</h2>

        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-2xl font-bold text-gray-900 capitalize">
                {subscription?.tier.replace('_', ' ')}
              </span>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getTierBadgeColor(subscription?.tier || '')}`}>
                {subscription?.tier.replace('_', ' ').toUpperCase()}
              </span>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusBadgeColor(subscription?.status || '')}`}>
                {subscription?.status.toUpperCase()}
              </span>
            </div>
            {!isFreeTier && subscription?.current_period_end && (
              <p className="text-sm text-gray-600 mt-1">
                {subscription.cancel_at_period_end
                  ? `Cancels on ${formatDate(subscription.current_period_end)}`
                  : `Renews on ${formatDate(subscription.current_period_end)}`}
              </p>
            )}
          </div>

          {subscription?.has_stripe && isOwner && (
            <button
              onClick={handleManageBilling}
              disabled={portalLoading}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50"
            >
              {portalLoading ? 'Loading...' : 'Manage Billing'}
            </button>
          )}
        </div>

        {/* Plan Details */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-t pt-4">
          <div>
            <p className="text-sm text-gray-500">Cloud Accounts</p>
            <p className="text-lg font-medium text-gray-900">
              {subscription?.total_accounts_allowed === -1
                ? 'Unlimited'
                : subscription?.total_accounts_allowed}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Scans</p>
            <p className="text-lg font-medium text-gray-900">
              {isFreeTier
                ? subscription?.free_scan_used
                  ? 'Used (1 free scan)'
                  : '1 free scan available'
                : 'Unlimited'}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Data Retention</p>
            <p className="text-lg font-medium text-gray-900">
              {isFreeTier ? '7 days' : 'Unlimited'}
            </p>
          </div>
        </div>

        {/* Free Scan Status */}
        {isFreeTier && subscription?.free_scan_used && subscription.free_scan_expires_at && (
          <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-sm text-yellow-800">
              Your free scan results expire on {formatDate(subscription.free_scan_expires_at)}.
              Subscribe to keep your data and unlock unlimited scans.
            </p>
          </div>
        )}
      </div>

      {/* Upgrade Section (for free tier users) */}
      {isFreeTier && isOwner && pricing && (
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 shadow rounded-lg p-6 text-white">
          <h2 className="text-lg font-medium mb-2">Upgrade to Subscriber</h2>
          <p className="text-blue-100 mb-6">
            Get unlimited scans, historical trends, scheduled scans, alerts, and API access.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <p className="text-3xl font-bold">${pricing.subscriber_monthly_dollars}/mo</p>
              <p className="text-blue-100 text-sm">Includes {pricing.subscriber_tier_accounts} cloud accounts</p>

              <div className="mt-4">
                <label className="block text-sm font-medium text-blue-100 mb-1">
                  Additional accounts (+${pricing.additional_account_subscriber_dollars}/mo each)
                </label>
                <select
                  value={additionalAccounts}
                  onChange={(e) => setAdditionalAccounts(Number(e.target.value))}
                  className="w-32 px-3 py-2 border border-blue-400 bg-blue-500 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-white"
                >
                  {[0, 1, 2, 3, 4, 5, 10, 15, 20].map((n) => (
                    <option key={n} value={n}>
                      +{n}
                    </option>
                  ))}
                </select>
              </div>

              <p className="mt-4 text-lg font-medium">
                Total: ${(pricing.subscriber_monthly_dollars + additionalAccounts * pricing.additional_account_subscriber_dollars).toFixed(2)}/mo
              </p>
            </div>

            <div>
              <h3 className="font-medium mb-3">What's included:</h3>
              <ul className="space-y-2 text-sm text-blue-100">
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  Unlimited scans
                </li>
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  {pricing.subscriber_tier_accounts} cloud accounts (+ additional)
                </li>
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  Historical trends & analytics
                </li>
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  Scheduled scans
                </li>
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  Coverage change alerts
                </li>
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  API access
                </li>
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  Unlimited data retention
                </li>
              </ul>
            </div>
          </div>

          <button
            onClick={handleSubscribe}
            disabled={checkoutLoading}
            className="mt-6 w-full md:w-auto px-6 py-3 bg-white text-blue-600 font-medium rounded-md hover:bg-blue-50 disabled:opacity-50"
          >
            {checkoutLoading ? 'Redirecting to checkout...' : 'Subscribe Now'}
          </button>
        </div>
      )}

      {/* Non-owner upgrade notice */}
      {isFreeTier && !isOwner && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-blue-800">
            Contact your organization owner to upgrade your subscription.
          </p>
        </div>
      )}

      {/* Invoice History */}
      {invoices.length > 0 && (
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Invoice History</h2>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Amount</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Period</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {invoices.map((invoice) => (
                  <tr key={invoice.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {formatDate(invoice.created_at)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {formatCurrency(invoice.amount_cents)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={`px-2 py-1 rounded-full text-xs font-medium ${
                          invoice.status === 'paid'
                            ? 'bg-green-100 text-green-800'
                            : invoice.status === 'open'
                            ? 'bg-yellow-100 text-yellow-800'
                            : 'bg-gray-100 text-gray-800'
                        }`}
                      >
                        {invoice.status?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {invoice.period_start && invoice.period_end
                        ? `${formatDate(invoice.period_start)} - ${formatDate(invoice.period_end)}`
                        : '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      {invoice.invoice_pdf_url && (
                        <a
                          href={invoice.invoice_pdf_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800 mr-4"
                        >
                          PDF
                        </a>
                      )}
                      {invoice.hosted_invoice_url && (
                        <a
                          href={invoice.hosted_invoice_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800"
                        >
                          View
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Feature Comparison (for free tier) */}
      {isFreeTier && (
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Feature Comparison</h2>

          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr>
                  <th className="text-left text-sm font-medium text-gray-500 pb-4">Feature</th>
                  <th className="text-center text-sm font-medium text-gray-500 pb-4">Free Scan</th>
                  <th className="text-center text-sm font-medium text-gray-500 pb-4">Subscriber</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {[
                  { feature: 'Coverage Heatmap', free: true, paid: true },
                  { feature: 'Gap Analysis List', free: true, paid: true },
                  { feature: 'PDF Report Export', free: true, paid: true },
                  { feature: 'Cloud Accounts', free: '1', paid: '3+' },
                  { feature: 'Scans', free: '1', paid: 'Unlimited' },
                  { feature: 'Data Retention', free: '7 days', paid: 'Forever' },
                  { feature: 'Historical Trends', free: false, paid: true },
                  { feature: 'Scheduled Scans', free: false, paid: true },
                  { feature: 'Coverage Alerts', free: false, paid: true },
                  { feature: 'API Access', free: false, paid: true },
                ].map((row, idx) => (
                  <tr key={idx}>
                    <td className="py-3 text-sm text-gray-900">{row.feature}</td>
                    <td className="py-3 text-center">
                      {typeof row.free === 'boolean' ? (
                        row.free ? (
                          <svg className="h-5 w-5 text-green-500 mx-auto" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                          </svg>
                        ) : (
                          <svg className="h-5 w-5 text-gray-300 mx-auto" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                          </svg>
                        )
                      ) : (
                        <span className="text-sm text-gray-600">{row.free}</span>
                      )}
                    </td>
                    <td className="py-3 text-center">
                      {typeof row.paid === 'boolean' ? (
                        row.paid ? (
                          <svg className="h-5 w-5 text-green-500 mx-auto" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                          </svg>
                        ) : (
                          <svg className="h-5 w-5 text-gray-300 mx-auto" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                          </svg>
                        )
                      ) : (
                        <span className="text-sm text-gray-900 font-medium">{row.paid}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
