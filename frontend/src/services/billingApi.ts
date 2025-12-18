import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1/billing',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface Subscription {
  id?: string
  tier: 'free_scan' | 'subscriber' | 'enterprise'
  status: 'active' | 'past_due' | 'canceled' | 'unpaid'
  free_scan_used: boolean
  free_scan_at?: string
  free_scan_expires_at?: string
  can_scan: boolean
  included_accounts: number
  additional_accounts: number
  total_accounts_allowed: number
  current_period_start?: string
  current_period_end?: string
  cancel_at_period_end: boolean
  has_stripe: boolean
}

export interface Pricing {
  subscriber_monthly_cents: number
  subscriber_monthly_dollars: number
  enterprise_monthly_cents: number
  enterprise_monthly_dollars: number
  additional_account_subscriber_cents: number
  additional_account_subscriber_dollars: number
  free_tier_accounts: number
  subscriber_tier_accounts: number
  enterprise_included_accounts: number
  free_scan_retention_days: number
  volume_tiers: Array<{
    min_accounts: number
    max_accounts: number | string
    price_per_account_cents: number
    price_per_account_dollars: number
    label: string
  }>
}

export interface Invoice {
  id: string
  stripe_invoice_id: string
  amount_cents: number
  amount_dollars: number
  currency: string
  status?: string
  invoice_pdf_url?: string
  hosted_invoice_url?: string
  period_start?: string
  period_end?: string
  paid_at?: string
  created_at: string
}

export interface CheckoutResponse {
  checkout_url: string
  session_id: string
}

export interface PortalResponse {
  portal_url: string
}

// API functions
export const billingApi = {
  // Get subscription info
  getSubscription: async (token: string): Promise<Subscription> => {
    const response = await api.get<Subscription>('/subscription', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Get pricing info
  getPricing: async (token: string): Promise<Pricing> => {
    const response = await api.get<Pricing>('/pricing', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Create checkout session
  createCheckout: async (
    token: string,
    successUrl: string,
    cancelUrl: string,
    additionalAccounts: number = 0
  ): Promise<CheckoutResponse> => {
    const response = await api.post<CheckoutResponse>(
      '/checkout',
      {
        success_url: successUrl,
        cancel_url: cancelUrl,
        additional_accounts: additionalAccounts,
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    )
    return response.data
  },

  // Create portal session
  createPortal: async (token: string, returnUrl: string): Promise<PortalResponse> => {
    const response = await api.post<PortalResponse>(
      '/portal',
      { return_url: returnUrl },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    )
    return response.data
  },

  // Get invoices
  getInvoices: async (token: string, limit: number = 10): Promise<Invoice[]> => {
    const response = await api.get<Invoice[]>('/invoices', {
      headers: { Authorization: `Bearer ${token}` },
      params: { limit },
    })
    return response.data
  },
}

export default billingApi
