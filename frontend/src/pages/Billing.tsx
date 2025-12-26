import { useState, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'
import {
  billingApi,
  Subscription,
  Invoice,
  Pricing,
  isFreeTier as checkIsFreeTier,
  getTierDisplayName,
} from '../services/billingApi'

export default function Billing() {
  const { token, user } = useAuth()
  const [subscription, setSubscription] = useState<Subscription | null>(null)
  const [invoices, setInvoices] = useState<Invoice[]>([])
  const [pricing, setPricing] = useState<Pricing | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [checkoutLoading, setCheckoutLoading] = useState(false)
  const [portalLoading, setPortalLoading] = useState(false)

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
      const [subData, invoicesData, pricingData] = await Promise.all([
        billingApi.getSubscription(token),
        billingApi.getInvoices(token),
        billingApi.getPricing(token),
      ])
      setSubscription(subData)
      setInvoices(invoicesData)
      setPricing(pricingData)
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
        0  // No additional accounts in new simplified pricing
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

  const formatCurrency = (pence: number) => {
    return new Intl.NumberFormat('en-GB', {
      style: 'currency',
      currency: 'GBP',
    }).format(pence / 100)
  }

  const formatRetention = (days: number | null | undefined) => {
    if (days === null || days === undefined) return 'Unlimited'
    if (days >= 365) return days === 365 ? '1 year' : `${Math.round(days / 365)} years`
    return `${days} days`
  }

  const getTierInfo = (tierName: string) => {
    return pricing?.tiers?.find(t => t.tier === tierName)
  }

  const formatAccounts = (maxAccounts: number | null | undefined) => {
    if (maxAccounts === null || maxAccounts === undefined) return 'Unlimited'
    return String(maxAccounts)
  }

  const getTierBadgeColor = (tier: string) => {
    switch (tier) {
      case 'individual':
        return 'bg-blue-900/30 text-blue-400'
      case 'pro':
        return 'bg-cyan-900/30 text-cyan-400'
      case 'enterprise':
        return 'bg-purple-900/30 text-purple-400'
      case 'free':
      case 'free_scan':
        return 'bg-gray-700/30 text-gray-400'
      // Legacy tier
      case 'subscriber':
        return 'bg-blue-900/30 text-blue-400'
      default:
        return 'bg-gray-700/30 text-gray-400'
    }
  }

  const getStatusBadgeColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-900/30 text-green-400'
      case 'past_due':
        return 'bg-yellow-900/30 text-yellow-400'
      case 'canceled':
        return 'bg-red-900/30 text-red-400'
      default:
        return 'bg-gray-700/30 text-gray-400'
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

  const isFreeTier = subscription ? checkIsFreeTier(subscription.tier) : false
  const isOwner = user?.role === 'owner'

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Billing & Subscription</h1>
        <p className="mt-1 text-sm text-gray-400">
          Manage your subscription and billing details
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* Current Plan */}
      <div className="bg-gray-800 shadow-sm rounded-lg border border-gray-700 p-6">
        <h2 className="text-lg font-medium text-white mb-4">Current Plan</h2>

        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-2xl font-bold text-white">
                {subscription ? getTierDisplayName(subscription.tier) : 'Free'}
              </span>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getTierBadgeColor(subscription?.tier || '')}`}>
                {subscription ? getTierDisplayName(subscription.tier).toUpperCase() : 'FREE'}
              </span>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusBadgeColor(subscription?.status || '')}`}>
                {subscription?.status.toUpperCase()}
              </span>
            </div>
            {!isFreeTier && subscription?.current_period_end && (
              <p className="text-sm text-gray-400 mt-1">
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
              className="px-4 py-2 text-sm font-medium border border-gray-600 bg-gray-800 text-gray-100 rounded-md hover:bg-gray-700 disabled:opacity-50"
            >
              {portalLoading ? 'Loading...' : 'Manage Billing'}
            </button>
          )}
        </div>

        {/* Plan Details */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-t border-gray-700 pt-4">
          <div>
            <p className="text-sm text-gray-400">Cloud Accounts</p>
            <p className="text-lg font-medium text-white">
              {subscription?.total_accounts_allowed === -1
                ? 'Unlimited'
                : subscription?.total_accounts_allowed}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400">Scans</p>
            <p className="text-lg font-medium text-white">
              {isFreeTier
                ? subscription?.free_scan_used
                  ? 'Used (1 free scan)'
                  : '1 free scan available'
                : 'Unlimited'}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400">Data Retention</p>
            <p className="text-lg font-medium text-white">
              {formatRetention(subscription?.history_retention_days)}
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
      {isFreeTier && isOwner && (() => {
        const individualTier = getTierInfo('individual')
        const accountLimit = individualTier?.max_accounts ?? 6
        const retentionDays = individualTier?.history_retention_days ?? 90
        const priceMonthly = individualTier?.price_monthly_pounds ?? 29
        return (
        <div className="bg-gradient-to-r from-blue-600 to-cyan-600 shadow rounded-lg p-6 text-white">
          <h2 className="text-lg font-medium mb-2">Upgrade to Individual</h2>
          <p className="text-blue-100 mb-6">
            Get up to {accountLimit} accounts, {formatRetention(retentionDays)} data retention, scheduled scans, alerts, and API access.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <p className="text-3xl font-bold">£{priceMonthly}/mo</p>
              <p className="text-blue-100 text-sm">Up to {accountLimit} cloud accounts included</p>
              <p className="text-blue-100 text-xs mt-2">No per-account fees - simple flat pricing</p>
            </div>

            <div>
              <h3 className="font-medium mb-3">What&apos;s included:</h3>
              <ul className="space-y-2 text-sm text-blue-100">
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  Up to {accountLimit} cloud accounts (AWS + GCP)
                </li>
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
                  {formatRetention(retentionDays)} data retention
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
                  Scheduled scans & alerts
                </li>
                <li className="flex items-center gap-2">
                  <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                  API access & code analysis
                </li>
              </ul>
            </div>
          </div>

          <button
            onClick={handleSubscribe}
            disabled={checkoutLoading}
            className="mt-6 w-full md:w-auto px-6 py-3 bg-white text-blue-600 font-medium rounded-md hover:bg-blue-900/30 disabled:opacity-50"
          >
            {checkoutLoading ? 'Redirecting to checkout...' : 'Upgrade to Individual'}
          </button>
        </div>
        )
      })()}

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
        <div className="bg-gray-800 shadow-sm rounded-lg border border-gray-700 p-6">
          <h2 className="text-lg font-medium text-white mb-4">Invoice History</h2>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-700">
              <thead className="bg-gray-700/30">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Amount</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Period</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-gray-800 divide-y divide-gray-700">
                {invoices.map((invoice) => (
                  <tr key={invoice.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-white">
                      {formatDate(invoice.created_at)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-white">
                      {formatCurrency(invoice.amount_cents)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={`px-2 py-1 rounded-full text-xs font-medium ${
                          invoice.status === 'paid'
                            ? 'bg-green-900/30 text-green-400'
                            : invoice.status === 'open'
                            ? 'bg-yellow-900/30 text-yellow-400'
                            : 'bg-gray-700/30 text-gray-400'
                        }`}
                      >
                        {invoice.status?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
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
                          className="text-blue-400 hover:text-blue-300 mr-4"
                        >
                          PDF
                        </a>
                      )}
                      {invoice.hosted_invoice_url && (
                        <a
                          href={invoice.hosted_invoice_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:text-blue-300"
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
        <div className="bg-gray-800 shadow-sm rounded-lg border border-gray-700 p-6">
          <h2 className="text-lg font-medium text-white mb-4">Feature Comparison</h2>

          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr>
                  <th className="text-left text-sm font-medium text-gray-400 pb-4">Feature</th>
                  <th className="text-center text-sm font-medium text-gray-400 pb-4">Free</th>
                  <th className="text-center text-sm font-medium text-blue-400 pb-4">Individual</th>
                  <th className="text-center text-sm font-medium text-cyan-400 pb-4">Pro</th>
                  <th className="text-center text-sm font-medium text-purple-400 pb-4">Enterprise</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {[
                  {
                    feature: 'Cloud Accounts',
                    free: formatAccounts(getTierInfo('free')?.max_accounts),
                    individual: formatAccounts(getTierInfo('individual')?.max_accounts),
                    pro: formatAccounts(getTierInfo('pro')?.max_accounts),
                    enterprise: formatAccounts(getTierInfo('enterprise')?.max_accounts)
                  },
                  {
                    feature: 'Data Retention',
                    free: formatRetention(getTierInfo('free')?.history_retention_days),
                    individual: formatRetention(getTierInfo('individual')?.history_retention_days),
                    pro: formatRetention(getTierInfo('pro')?.history_retention_days),
                    enterprise: formatRetention(getTierInfo('enterprise')?.history_retention_days)
                  },
                  { feature: 'Coverage Heatmap', free: true, individual: true, pro: true, enterprise: true },
                  { feature: 'Gap Analysis', free: true, individual: true, pro: true, enterprise: true },
                  { feature: 'Export Reports (PDF/CSV)', free: false, individual: true, pro: true, enterprise: true },
                  { feature: 'Remediation Templates', free: true, individual: true, pro: true, enterprise: true },
                  { feature: 'Historical Trends', free: false, individual: true, pro: true, enterprise: true },
                  { feature: 'Scheduled Scans', free: false, individual: true, pro: true, enterprise: true },
                  { feature: 'Coverage Alerts', free: false, individual: true, pro: true, enterprise: true },
                  { feature: 'API Access', free: false, individual: true, pro: true, enterprise: true },
                  { feature: 'Code Analysis', free: false, individual: true, pro: true, enterprise: true },
                  { feature: 'Organisation Features', free: false, individual: false, pro: true, enterprise: true },
                  { feature: 'SSO / SAML', free: false, individual: false, pro: false, enterprise: true },
                  { feature: 'Dedicated Support', free: false, individual: false, pro: false, enterprise: true },
                ].map((row, idx) => (
                  <tr key={idx}>
                    <td className="py-3 text-sm text-white">{row.feature}</td>
                    {['free', 'individual', 'pro', 'enterprise'].map((tier) => {
                      const value = row[tier as keyof typeof row]
                      return (
                        <td key={tier} className="py-3 text-center">
                          {typeof value === 'boolean' ? (
                            value ? (
                              <svg className="h-5 w-5 text-green-400 mx-auto" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                              </svg>
                            ) : (
                              <svg className="h-5 w-5 text-gray-400 mx-auto" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                              </svg>
                            )
                          ) : (
                            <span className={`text-sm ${tier === 'free' ? 'text-gray-400' : 'text-white font-medium'}`}>{value}</span>
                          )}
                        </td>
                      )
                    })}
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
