import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
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

export default function Organizations() {
  const queryClient = useQueryClient()
  const [showConnectModal, setShowConnectModal] = useState(false)

  const { data: organizations, isLoading, error } = useQuery({
    queryKey: ['cloud-organizations'],
    queryFn: cloudOrganizationsApi.list,
    retry: (failureCount, error: unknown) => {
      // Don't retry on 403 (feature not available)
      const axiosError = error as { response?: { status?: number } }
      if (axiosError?.response?.status === 403) return false
      return failureCount < 3
    },
  })

  // Check if this is a 403 feature-not-available error
  const isFeatureRestricted = (error as { response?: { status?: number } })?.response?.status === 403

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
            <h1 className="text-2xl font-bold text-gray-900">
              Cloud Organisations
            </h1>
            <p className="text-gray-600">
              Connect and manage your AWS and GCP organisations
            </p>
          </div>
        </div>

        <div className="text-center py-16 card">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-purple-100 mb-6">
            <Lock className="h-8 w-8 text-purple-600" />
          </div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">
            Pro Feature
          </h2>
          <p className="text-gray-600 max-w-md mx-auto mb-6">
            Cloud Organisations is a Pro feature that lets you manage entire AWS
            Organisations or GCP Organisations from a single view.
          </p>
          <div className="bg-gray-50 rounded-lg p-4 max-w-md mx-auto mb-6">
            <h3 className="font-medium text-gray-900 mb-2 flex items-center justify-center">
              <Network className="h-5 w-5 mr-2 text-purple-600" />
              What you get with Pro
            </h3>
            <ul className="text-sm text-gray-600 space-y-1 text-left ml-6">
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
          <h1 className="text-2xl font-bold text-gray-900">
            Cloud Organisations
          </h1>
          <p className="text-gray-600">
            Connect and manage your AWS and GCP organisations
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
      {!organizations?.length && (
        <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <h3 className="font-semibold text-blue-900 flex items-center">
            <Network className="h-5 w-5 mr-2" />
            Why connect an organisation?
          </h3>
          <ul className="mt-2 text-sm text-blue-800 space-y-1 ml-7">
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
      {!organizations?.length ? (
        <div className="text-center py-12 card">
          <Building2 className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-gray-900">
            No organisations connected
          </h3>
          <p className="mt-1 text-sm text-gray-500">
            Connect your AWS or GCP organisation to get started.
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
          {organizations.map((org) => (
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
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h2 className="text-lg font-semibold mb-4">Connect Organisation</h2>
            <p className="text-gray-600 mb-6">
              Choose your cloud provider to get started.
            </p>
            <div className="space-y-3">
              <Link
                to="/organizations/connect?provider=aws"
                className="flex items-center justify-between p-4 border rounded-lg hover:border-orange-500 hover:bg-orange-50"
                onClick={() => setShowConnectModal(false)}
              >
                <div className="flex items-center">
                  <div className="p-2 bg-orange-100 rounded-lg mr-3">
                    <Cloud className="h-6 w-6 text-orange-600" />
                  </div>
                  <div>
                    <div className="font-medium">AWS Organisation</div>
                    <div className="text-sm text-gray-500">
                      Connect via management account
                    </div>
                  </div>
                </div>
                <ChevronRight className="h-5 w-5 text-gray-400" />
              </Link>
              <Link
                to="/organizations/connect?provider=gcp"
                className="flex items-center justify-between p-4 border rounded-lg hover:border-blue-500 hover:bg-blue-50"
                onClick={() => setShowConnectModal(false)}
              >
                <div className="flex items-center">
                  <div className="p-2 bg-blue-100 rounded-lg mr-3">
                    <Cloud className="h-6 w-6 text-blue-600" />
                  </div>
                  <div>
                    <div className="font-medium">GCP Organisation</div>
                    <div className="text-sm text-gray-500">
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
      ? 'bg-blue-100 text-blue-600'
      : 'bg-orange-100 text-orange-600'

  const getStatusBadge = () => {
    switch (organization.status) {
      case 'active':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-green-100 text-green-800 flex items-center">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            Active
          </span>
        )
      case 'discovering':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800 flex items-center">
            <Loader2 className="w-3 h-3 mr-1 animate-spin" />
            Discovering
          </span>
        )
      case 'partial':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-yellow-100 text-yellow-800 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Partial
          </span>
        )
      case 'error':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Error
          </span>
        )
      default:
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-800">
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
                className="font-semibold text-gray-900 hover:text-blue-600"
              >
                {organization.name}
              </Link>
              {getStatusBadge()}
            </div>
            <p className="text-sm text-gray-500">
              {organization.provider.toUpperCase()} Organisation{' '}
              {organization.cloud_org_id}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          {/* Account stats */}
          <div className="text-right mr-4">
            <div className="text-lg font-semibold text-gray-900">
              {organization.total_accounts_connected}/
              {organization.total_accounts_discovered}
            </div>
            <div className="text-xs text-gray-500">accounts connected</div>
          </div>

          <Link
            to={`/organizations/${organization.id}`}
            className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg"
            title="View Dashboard"
          >
            <BarChart3 className="h-5 w-5" />
          </Link>

          <button
            onClick={onSync}
            disabled={isSyncing}
            className="p-2 text-gray-600 hover:bg-gray-50 rounded-lg"
            title="Sync Organisation"
          >
            <RefreshCw
              className={`h-5 w-5 ${isSyncing ? 'animate-spin' : ''}`}
            />
          </button>

          <button
            onClick={onDelete}
            disabled={isDeleting}
            className="p-2 text-red-600 hover:bg-red-50 rounded-lg"
            title="Disconnect Organisation"
          >
            <Trash2 className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Additional info */}
      <div className="mt-3 flex items-center justify-between text-sm text-gray-500">
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
          className="text-blue-600 hover:underline text-sm"
        >
          Manage accounts &rarr;
        </Link>
      </div>
    </div>
  )
}
