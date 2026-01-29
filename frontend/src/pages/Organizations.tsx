import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router'
import {
  Building2,
  Plus,
  RefreshCw,
  Trash2,
  ChevronRight,
  Cloud,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Network,
  BarChart3,
  Lock,
} from 'lucide-react'
import {
  cloudOrganizationsApi,
  CloudOrganization,
} from '../services/organizationsApi'
import { billingApi, Subscription, hasOrgFeatures } from '../services/billingApi'
import { useAuthStore } from '../stores/authStore'

export default function Organizations() {
  const queryClient = useQueryClient()
  const [showConnectModal, setShowConnectModal] = useState(false)
  const accessToken = useAuthStore((state) => state.accessToken)

  // Fetch subscription to check tier before making org API calls
  const { data: subscription, isLoading: subscriptionLoading } = useQuery<Subscription>({
    queryKey: ['subscription'],
    queryFn: () => billingApi.getSubscription(accessToken!),
    enabled: !!accessToken,
  })

  // Check if user has org features (Pro/Enterprise only)
  const canAccessOrgFeatures = subscription ? hasOrgFeatures(subscription.tier) : false

  const { data: organizations, isLoading: orgsLoading } = useQuery({
    queryKey: ['cloud-organizations'],
    queryFn: cloudOrganizationsApi.list,
    // Only fetch if user has Pro/Enterprise tier - prevents 403 errors
    enabled: canAccessOrgFeatures,
  })

  const isLoading = subscriptionLoading || (canAccessOrgFeatures && orgsLoading)

  // Show upgrade message for users without org features (Free/Individual)
  const isFeatureRestricted = subscription && !hasOrgFeatures(subscription.tier)

  // Ensure organizations is always an array to prevent .map errors
  const safeOrganizations = Array.isArray(organizations) ? organizations : []

  const syncMutation = useMutation({
    mutationFn: cloudOrganizationsApi.sync,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-organizations'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: cloudOrganizationsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-organizations'] })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
      </div>
    )
  }

  // Show upgrade message for users without org features
  if (isFeatureRestricted) {
    return (
      <div>
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white">
              Cloud Organisations
            </h1>
            <p className="text-gray-400">
              Connect and manage your AWS, GCP and Azure organisations
            </p>
          </div>
        </div>

        <div className="text-center py-16 card">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-purple-900/30 mb-6">
            <Lock className="h-8 w-8 text-purple-400" />
          </div>
          <h2 className="text-xl font-semibold text-white mb-2">
            Pro Feature
          </h2>
          <p className="text-gray-400 max-w-md mx-auto mb-6">
            Cloud Organisations is a Pro feature that lets you manage entire AWS
            Organisations or GCP Organisations from a single view.
          </p>
          <div className="bg-gray-700/30 rounded-lg p-4 max-w-md mx-auto mb-6">
            <h3 className="font-medium text-white mb-2 flex items-center justify-center">
              <Network className="h-5 w-5 mr-2 text-purple-400" />
              What you get with Pro
            </h3>
            <ul className="text-sm text-gray-400 space-y-1 text-left ml-6">
              <li>• Automatically discover all accounts in your organisation</li>
              <li>• Aggregate coverage view across all accounts</li>
              <li>• Detect organisation-level security controls</li>
              <li>• Identify cross-account coverage gaps</li>
            </ul>
          </div>
          <Link
            to="/settings/billing"
            className="inline-flex items-center px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 font-medium"
          >
            Upgrade to Pro
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Cloud Organisations
          </h1>
          <p className="text-gray-400">
            Connect and manage your AWS, GCP and Azure organisations
          </p>
        </div>
        <Link
          to="/organizations/connect"
          className="btn-primary flex items-center"
        >
          <Plus className="h-4 w-4 mr-2" />
          Connect Organisation
        </Link>
      </div>

      {/* Info banner for org benefits */}
      {!safeOrganizations.length && (
        <div className="mb-6 p-4 bg-blue-900/30 border border-blue-700 rounded-lg">
          <h3 className="font-semibold text-blue-400 flex items-center">
            <Network className="h-5 w-5 mr-2" />
            Why connect an organisation?
          </h3>
          <ul className="mt-2 text-sm text-blue-400 space-y-1 ml-7">
            <li>
              Automatically discover all accounts/projects in your cloud
              organisation
            </li>
            <li>
              See aggregate coverage across your entire organisation
            </li>
            <li>
              Detect organisation-level security controls (org CloudTrail, SCC,
              etc.)
            </li>
            <li>Identify coverage gaps at the organisation level</li>
          </ul>
        </div>
      )}

      {/* Organisations List */}
      {!safeOrganizations.length ? (
        <div className="text-center py-12 card">
          <Building2 className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-white">
            No organisations connected
          </h3>
          <p className="mt-1 text-sm text-gray-400">
            Connect your AWS, GCP or Azure organisation to get started.
          </p>
          <Link
            to="/organizations/connect"
            className="mt-4 inline-flex btn-primary"
          >
            <Plus className="h-4 w-4 mr-2" />
            Connect Organisation
          </Link>
        </div>
      ) : (
        <div className="space-y-4">
          {safeOrganizations.map((org) => (
            <OrganizationCard
              key={org.id}
              organization={org}
              onSync={() => syncMutation.mutate(org.id)}
              onDelete={() => {
                if (
                  confirm(
                    `Are you sure you want to disconnect "${org.name}"? This will not delete the connected accounts.`
                  )
                ) {
                  deleteMutation.mutate(org.id)
                }
              }}
              isSyncing={syncMutation.isPending}
              isDeleting={deleteMutation.isPending}
            />
          ))}
        </div>
      )}

      {/* Connect Modal - simplified, actual wizard is on separate page */}
      {showConnectModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 border border-gray-700">
            <h2 className="text-lg font-semibold text-white mb-4">Connect Organisation</h2>
            <p className="text-gray-300 mb-6">
              Choose your cloud provider to get started.
            </p>
            <div className="space-y-3">
              <Link
                to="/organizations/connect?provider=aws"
                className="flex items-center justify-between p-4 border rounded-lg hover:border-orange-500 hover:bg-gray-700"
                onClick={() => setShowConnectModal(false)}
              >
                <div className="flex items-center">
                  <div className="p-2 bg-orange-900/30 rounded-lg mr-3">
                    <Cloud className="h-6 w-6 text-orange-400" />
                  </div>
                  <div>
                    <div className="font-medium">AWS Organisation</div>
                    <div className="text-sm text-gray-400">
                      Connect via management account
                    </div>
                  </div>
                </div>
                <ChevronRight className="h-5 w-5 text-gray-400" />
              </Link>
              <Link
                to="/organizations/connect?provider=gcp"
                className="flex items-center justify-between p-4 border rounded-lg hover:border-blue-500 hover:bg-gray-700"
                onClick={() => setShowConnectModal(false)}
              >
                <div className="flex items-center">
                  <div className="p-2 bg-blue-900/30 rounded-lg mr-3">
                    <Cloud className="h-6 w-6 text-blue-400" />
                  </div>
                  <div>
                    <div className="font-medium">GCP Organisation</div>
                    <div className="text-sm text-gray-400">
                      Connect via service account
                    </div>
                  </div>
                </div>
                <ChevronRight className="h-5 w-5 text-gray-400" />
              </Link>
            </div>
            <button
              onClick={() => setShowConnectModal(false)}
              className="mt-4 w-full btn-secondary"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// Organisation Card Component
function OrganizationCard({
  organization,
  onSync,
  onDelete,
  isSyncing,
  isDeleting,
}: {
  organization: CloudOrganization
  onSync: () => void
  onDelete: () => void
  isSyncing: boolean
  isDeleting: boolean
}) {
  const providerColor =
    organization.provider === 'gcp'
      ? 'bg-blue-900/30 text-blue-400'
      : 'bg-orange-900/30 text-orange-400'

  const getStatusBadge = () => {
    switch (organization.status) {
      case 'active':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-green-900/30 text-green-400 flex items-center">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            Active
          </span>
        )
      case 'discovering':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-blue-900/30 text-blue-400 flex items-center">
            <Loader2 className="w-3 h-3 mr-1 animate-spin" />
            Discovering
          </span>
        )
      case 'partial':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-yellow-900/30 text-yellow-400 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Partial
          </span>
        )
      case 'error':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-red-900/30 text-red-400 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Error
          </span>
        )
      default:
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-gray-700/30 text-gray-400">
            {organization.status}
          </span>
        )
    }
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <div className={`p-2 rounded-lg ${providerColor}`}>
            <Building2 className="h-6 w-6" />
          </div>
          <div className="ml-4">
            <div className="flex items-center space-x-2">
              <Link
                to={`/organizations/${organization.id}`}
                className="font-semibold text-white hover:text-blue-400"
              >
                {organization.name}
              </Link>
              {getStatusBadge()}
            </div>
            <p className="text-sm text-gray-400">
              {organization.provider.toUpperCase()} Organisation{' '}
              {organization.cloud_org_id}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          {/* Account stats */}
          <div className="text-right mr-4">
            <div className="text-lg font-semibold text-white">
              {organization.total_accounts_connected}/
              {organization.total_accounts_discovered}
            </div>
            <div className="text-xs text-gray-400">accounts connected</div>
          </div>

          <Link
            to={`/organizations/${organization.id}`}
            className="p-2 text-blue-400 hover:bg-gray-700 rounded-lg"
            title="View Dashboard"
          >
            <BarChart3 className="h-5 w-5" />
          </Link>

          <button
            onClick={onSync}
            disabled={isSyncing}
            className="p-2 text-gray-400 hover:bg-gray-700 rounded-lg"
            title="Sync Organisation"
          >
            <RefreshCw
              className={`h-5 w-5 ${isSyncing ? 'animate-spin' : ''}`}
            />
          </button>

          <button
            onClick={onDelete}
            disabled={isDeleting}
            className="p-2 text-red-400 hover:bg-red-900/30 rounded-lg"
            title="Disconnect Organisation"
          >
            <Trash2 className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Additional info */}
      <div className="mt-3 flex items-center justify-between text-sm text-gray-400">
        <div className="flex items-center space-x-4">
          {organization.last_sync_at && (
            <span>
              Last synced:{' '}
              {new Date(organization.last_sync_at).toLocaleString()}
            </span>
          )}
        </div>
        <Link
          to={`/organizations/${organization.id}/members`}
          className="text-blue-400 hover:underline text-sm"
        >
          Manage accounts &rarr;
        </Link>
      </div>
    </div>
  )
}
