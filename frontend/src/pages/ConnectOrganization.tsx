import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Cloud,
  ChevronRight,
  ChevronLeft,
  Check,
  Loader2,
  AlertTriangle,
  ExternalLink,
} from 'lucide-react'
import { cloudOrganizationsApi } from '../services/organizationsApi'
import { PageHeader } from '../components/navigation'

type Provider = 'aws' | 'gcp' | null
type Step = 'provider' | 'credentials' | 'discovering' | 'complete'

export default function ConnectOrganization() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [searchParams] = useSearchParams()

  const initialProvider = searchParams.get('provider') as Provider
  const [step, setStep] = useState<Step>(initialProvider ? 'credentials' : 'provider')
  const [provider, setProvider] = useState<Provider>(initialProvider)
  const [error, setError] = useState<string | null>(null)

  // AWS credentials
  const [awsRoleArn, setAwsRoleArn] = useState('')

  // GCP credentials
  const [gcpOrgId, setGcpOrgId] = useState('')
  const [gcpServiceAccountEmail, setGcpServiceAccountEmail] = useState('')
  const [gcpProjectId, setGcpProjectId] = useState('')

  // Discovery result
  const [discoveryResult, setDiscoveryResult] = useState<{
    organization_id: string
    total_accounts_discovered: number
  } | null>(null)

  const discoverMutation = useMutation({
    mutationFn: cloudOrganizationsApi.discover,
    onSuccess: (data) => {
      setDiscoveryResult({
        organization_id: data.organization_id,
        total_accounts_discovered: data.total_accounts_discovered,
      })
      setStep('complete')
      queryClient.invalidateQueries({ queryKey: ['cloud-organizations'] })
    },
    onError: (err: Error) => {
      setError(err.message || 'Failed to discover organisation')
      setStep('credentials')
    },
  })

  const handleProviderSelect = (selectedProvider: 'aws' | 'gcp') => {
    setProvider(selectedProvider)
    setStep('credentials')
    setError(null)
  }

  const handleDiscover = () => {
    setError(null)
    setStep('discovering')

    if (provider === 'aws') {
      if (!awsRoleArn) {
        setError('IAM Role ARN is required')
        setStep('credentials')
        return
      }
      discoverMutation.mutate({
        provider: 'aws',
        credentials_arn: awsRoleArn,
      })
    } else if (provider === 'gcp') {
      if (!gcpOrgId) {
        setError('GCP Organisation ID is required')
        setStep('credentials')
        return
      }
      discoverMutation.mutate({
        provider: 'gcp',
        gcp_org_id: gcpOrgId,
        gcp_service_account_email: gcpServiceAccountEmail || undefined,
        gcp_project_id: gcpProjectId || undefined,
      })
    }
  }

  const handleComplete = () => {
    if (discoveryResult) {
      navigate(`/organizations/${discoveryResult.organization_id}/members`)
    } else {
      navigate('/organizations')
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <PageHeader
        title="Connect Cloud Organisation"
        description="Connect your AWS or GCP organisation to discover all accounts"
        back={{ label: "Organisations", fallback: "/organizations" }}
      />

      {/* Progress Steps */}
      <div className="flex items-center mb-8">
        {['provider', 'credentials', 'discovering', 'complete'].map(
          (s, idx) => (
            <div key={s} className="flex items-center">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                  step === s
                    ? 'bg-blue-600 text-white'
                    : ['provider', 'credentials', 'discovering', 'complete'].indexOf(step) > idx
                    ? 'bg-green-600 text-white'
                    : 'bg-gray-700 text-gray-400'
                }`}
              >
                {['provider', 'credentials', 'discovering', 'complete'].indexOf(step) > idx ? (
                  <Check className="h-4 w-4" />
                ) : (
                  idx + 1
                )}
              </div>
              {idx < 3 && (
                <div
                  className={`w-16 h-1 ${
                    ['provider', 'credentials', 'discovering', 'complete'].indexOf(step) > idx
                      ? 'bg-green-600'
                      : 'bg-gray-700'
                  }`}
                />
              )}
            </div>
          )
        )}
      </div>

      {/* Step Content */}
      <div className="card">
        {/* Step 1: Provider Selection */}
        {step === 'provider' && (
          <div>
            <h2 className="text-lg font-semibold mb-4">
              Select Cloud Provider
            </h2>
            <div className="space-y-3">
              <button
                onClick={() => handleProviderSelect('aws')}
                className="w-full flex items-center justify-between p-4 border border-gray-700 rounded-lg hover:border-orange-500 hover:bg-orange-900/30"
              >
                <div className="flex items-center">
                  <div className="p-2 bg-orange-900/30 rounded-lg mr-3">
                    <Cloud className="h-6 w-6 text-orange-400" />
                  </div>
                  <div className="text-left">
                    <div className="font-medium">AWS Organisation</div>
                    <div className="text-sm text-gray-400">
                      Connect via IAM role in management account
                    </div>
                  </div>
                </div>
                <ChevronRight className="h-5 w-5 text-gray-400" />
              </button>
              <button
                onClick={() => handleProviderSelect('gcp')}
                className="w-full flex items-center justify-between p-4 border border-gray-700 rounded-lg hover:border-blue-500 hover:bg-blue-900/30"
              >
                <div className="flex items-center">
                  <div className="p-2 bg-blue-900/30 rounded-lg mr-3">
                    <Cloud className="h-6 w-6 text-blue-400" />
                  </div>
                  <div className="text-left">
                    <div className="font-medium">GCP Organisation</div>
                    <div className="text-sm text-gray-400">
                      Connect via service account with org-level permissions
                    </div>
                  </div>
                </div>
                <ChevronRight className="h-5 w-5 text-gray-400" />
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Credentials */}
        {step === 'credentials' && provider === 'aws' && (
          <div>
            <h2 className="text-lg font-semibold mb-4">
              AWS Organisation Credentials
            </h2>
            <p className="text-gray-400 mb-6">
              Provide an IAM role ARN from your AWS management account with
              organisation read permissions.
            </p>

            {error && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-800 flex items-center">
                <AlertTriangle className="h-4 w-4 mr-2" />
                {error}
              </div>
            )}

            {/* Required Permissions */}
            <div className="mb-6 p-4 bg-gray-700/30 rounded-lg">
              <h3 className="font-medium text-sm text-gray-400 mb-2">
                Required Permissions
              </h3>
              <div className="text-sm text-gray-400 space-y-1">
                <code className="block bg-gray-700 px-2 py-1 rounded-sm text-xs">
                  organizations:Describe*
                </code>
                <code className="block bg-gray-700 px-2 py-1 rounded-sm text-xs">
                  organizations:List*
                </code>
                <code className="block bg-gray-700 px-2 py-1 rounded-sm text-xs">
                  sts:AssumeRole (for member accounts)
                </code>
              </div>
              <a
                href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_permissions.html"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline text-sm mt-2 inline-flex items-center"
              >
                View AWS documentation
                <ExternalLink className="h-3 w-3 ml-1" />
              </a>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  IAM Role ARN *
                </label>
                <input
                  type="text"
                  value={awsRoleArn}
                  onChange={(e) => setAwsRoleArn(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="arn:aws:iam::123456789012:role/OrgReadOnlyRole"
                />
              </div>
            </div>

            <div className="flex justify-between mt-6">
              <button
                onClick={() => {
                  setStep('provider')
                  setProvider(null)
                }}
                className="btn-secondary flex items-center"
              >
                <ChevronLeft className="h-4 w-4 mr-1" />
                Back
              </button>
              <button
                onClick={handleDiscover}
                disabled={!awsRoleArn}
                className="btn-primary flex items-center"
              >
                Discover Organisation
                <ChevronRight className="h-4 w-4 ml-1" />
              </button>
            </div>
          </div>
        )}

        {step === 'credentials' && provider === 'gcp' && (
          <div>
            <h2 className="text-lg font-semibold mb-4">
              GCP Organisation Credentials
            </h2>
            <p className="text-gray-400 mb-6">
              Provide your GCP organisation ID and service account details.
            </p>

            {error && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-800 flex items-center">
                <AlertTriangle className="h-4 w-4 mr-2" />
                {error}
              </div>
            )}

            {/* Required Permissions */}
            <div className="mb-6 p-4 bg-gray-700/30 rounded-lg">
              <h3 className="font-medium text-sm text-gray-400 mb-2">
                Required Permissions
              </h3>
              <div className="text-sm text-gray-400 space-y-1">
                <code className="block bg-gray-700 px-2 py-1 rounded-sm text-xs">
                  resourcemanager.organizations.get
                </code>
                <code className="block bg-gray-700 px-2 py-1 rounded-sm text-xs">
                  resourcemanager.folders.list
                </code>
                <code className="block bg-gray-700 px-2 py-1 rounded-sm text-xs">
                  resourcemanager.projects.list
                </code>
              </div>
              <a
                href="https://cloud.google.com/resource-manager/docs/access-control-org"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline text-sm mt-2 inline-flex items-center"
              >
                View GCP documentation
                <ExternalLink className="h-3 w-3 ml-1" />
              </a>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Organisation ID *
                </label>
                <input
                  type="text"
                  value={gcpOrgId}
                  onChange={(e) => setGcpOrgId(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="123456789012"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Numeric organisation ID (find in Cloud Console &gt;
                  IAM &gt; Settings)
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Service Account Email
                </label>
                <input
                  type="text"
                  value={gcpServiceAccountEmail}
                  onChange={(e) => setGcpServiceAccountEmail(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="my-sa@my-project.iam.gserviceaccount.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Project ID
                </label>
                <input
                  type="text"
                  value={gcpProjectId}
                  onChange={(e) => setGcpProjectId(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="my-project-id"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Project where the service account resides
                </p>
              </div>
            </div>

            <div className="flex justify-between mt-6">
              <button
                onClick={() => {
                  setStep('provider')
                  setProvider(null)
                }}
                className="btn-secondary flex items-center"
              >
                <ChevronLeft className="h-4 w-4 mr-1" />
                Back
              </button>
              <button
                onClick={handleDiscover}
                disabled={!gcpOrgId}
                className="btn-primary flex items-center"
              >
                Discover Organisation
                <ChevronRight className="h-4 w-4 ml-1" />
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Discovering */}
        {step === 'discovering' && (
          <div className="text-center py-8">
            <Loader2 className="h-12 w-12 animate-spin text-blue-600 mx-auto mb-4" />
            <h2 className="text-lg font-semibold mb-2">
              Discovering Organisation
            </h2>
            <p className="text-gray-400">
              {provider === 'aws'
                ? 'Listing AWS accounts and organisational units...'
                : 'Listing GCP projects and folders...'}
            </p>
          </div>
        )}

        {/* Step 4: Complete */}
        {step === 'complete' && discoveryResult && (
          <div className="text-center py-8">
            <div className="w-16 h-16 bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
              <Check className="h-8 w-8 text-green-400" />
            </div>
            <h2 className="text-lg font-semibold mb-2">
              Organisation Discovered!
            </h2>
            <p className="text-gray-400 mb-6">
              Found {discoveryResult.total_accounts_discovered}{' '}
              {provider === 'aws' ? 'accounts' : 'projects'} in your
              organisation.
            </p>

            <div className="bg-blue-900/30 p-4 rounded-lg text-left mb-6">
              <h3 className="font-medium text-blue-400 mb-2">Next Steps</h3>
              <ul className="text-sm text-blue-400 space-y-1">
                <li>
                  1. Select which accounts to connect for scanning
                </li>
                <li>
                  2. Configure credentials for selected accounts
                </li>
                <li>
                  3. Run scans to discover detection coverage
                </li>
              </ul>
            </div>

            <button onClick={handleComplete} className="btn-primary">
              Continue to Account Selection
              <ChevronRight className="h-4 w-4 ml-1 inline" />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
