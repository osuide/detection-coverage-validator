import axios from 'axios'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/billing`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types

// New simplified tiers (2024-12)
export type AccountTier = 'free' | 'individual' | 'pro' | 'enterprise'
// Legacy tiers (deprecated, kept for backward compatibility)
export type LegacyTier = 'free_scan' | 'subscriber'
// Combined tier type
export type SubscriptionTier = AccountTier | LegacyTier

export interface Subscription {
  id?: string
  tier: SubscriptionTier
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
  // New tier-based fields
  max_accounts?: number | null
  max_team_members?: number | null
  org_features_enabled?: boolean
  history_retention_days?: number | null
}

export interface Pricing {
  // Legacy fields (kept for backward compatibility)
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
  // New tier information (optional for backward compatibility)
  tiers?: TierInfo[]
}

// New tier pricing information
export interface TierInfo {
  tier: AccountTier
  display_name: string
  price_monthly_cents: number | null
  price_monthly_dollars: number | null
  max_accounts: number | null
  max_team_members: number | null
  history_retention_days: number | null
  org_features: boolean
  is_custom_pricing: boolean
  key_features: string[]
}

// Helper functions for tier checking
export const isFreeTier = (tier: SubscriptionTier): boolean => {
  return tier === 'free' || tier === 'free_scan'
}

export const isLegacyTier = (tier: SubscriptionTier): boolean => {
  return tier === 'free_scan' || tier === 'subscriber'
}

export const hasOrgFeatures = (tier: SubscriptionTier): boolean => {
  return tier === 'pro' || tier === 'enterprise'
}

export const getTierDisplayName = (tier: SubscriptionTier): string => {
  switch (tier) {
    case 'free':
      return 'Free'
    case 'individual':
      return 'Individual'
    case 'pro':
      return 'Pro'
    case 'enterprise':
      return 'Enterprise'
    case 'free_scan':
      return 'Free (Legacy)'
    case 'subscriber':
      return 'Subscriber (Legacy)'
    default:
      return 'Unknown'
  }
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

export interface ScanStatus {
  can_scan: boolean
  scans_used: number
  scans_allowed: number
  unlimited: boolean
  next_available_at: string | null
  week_resets_at: string | null
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

  // Get scan status (limits and usage)
  getScanStatus: async (token: string): Promise<ScanStatus> => {
    const response = await api.get<ScanStatus>('/scan-status', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },
}

export default billingApi
