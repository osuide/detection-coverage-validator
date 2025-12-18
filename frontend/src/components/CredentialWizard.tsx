import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  X,
  ChevronRight,
  ChevronLeft,
  Download,
  Copy,
  Check,
  AlertCircle,
  CheckCircle2,
  Shield,
  Terminal,
  FileCode,
  Loader2,
  Info,
} from 'lucide-react'
import { credentialsApi } from '../services/api'

interface CredentialWizardProps {
  cloudAccountId: string
  provider: 'aws' | 'gcp'
  accountName: string
  onClose: () => void
  onSuccess: () => void
}

type WizardStep = 'instructions' | 'setup' | 'credentials' | 'validate'

export default function CredentialWizard({
  cloudAccountId,
  provider,
  accountName,
  onClose,
  onSuccess,
}: CredentialWizardProps) {
  const queryClient = useQueryClient()
  const [step, setStep] = useState<WizardStep>('instructions')
  const [copied, setCopied] = useState<string | null>(null)
  const [gcpCredentialType, setGcpCredentialType] = useState<'gcp_workload_identity' | 'gcp_service_account_key'>('gcp_workload_identity')

  // Form data
  const [awsRoleArn, setAwsRoleArn] = useState('')
  const [gcpServiceAccountEmail, setGcpServiceAccountEmail] = useState('')
  const [gcpServiceAccountKey, setGcpServiceAccountKey] = useState('')

  // Fetch setup instructions
  const { data: instructions, isLoading: instructionsLoading } = useQuery({
    queryKey: ['credentials', 'setup', cloudAccountId],
    queryFn: () => credentialsApi.getSetupInstructions(cloudAccountId),
  })

  // Fetch existing credential
  const { data: existingCredential, refetch: refetchCredential } = useQuery({
    queryKey: ['credentials', cloudAccountId],
    queryFn: () => credentialsApi.getCredential(cloudAccountId),
    retry: false,
  })

  // Create AWS credential
  const createAwsMutation = useMutation({
    mutationFn: (data: { cloud_account_id: string; role_arn: string }) =>
      credentialsApi.createAWSCredential(data),
    onSuccess: () => {
      refetchCredential()
      setStep('validate')
    },
  })

  // Create GCP credential
  const createGcpMutation = useMutation({
    mutationFn: (data: {
      cloud_account_id: string
      credential_type: 'gcp_workload_identity' | 'gcp_service_account_key'
      service_account_email?: string
      service_account_key?: string
    }) => credentialsApi.createGCPCredential(data),
    onSuccess: () => {
      refetchCredential()
      setStep('validate')
    },
  })

  // Validate credential
  const validateMutation = useMutation({
    mutationFn: () => credentialsApi.validate(cloudAccountId),
    onSuccess: (data) => {
      refetchCredential()
      if (data.status === 'valid') {
        queryClient.invalidateQueries({ queryKey: ['accounts'] })
        onSuccess()
      }
    },
  })

  const copyToClipboard = async (text: string, key: string) => {
    await navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 2000)
  }

  const handleSubmitCredentials = () => {
    if (provider === 'aws') {
      createAwsMutation.mutate({
        cloud_account_id: cloudAccountId,
        role_arn: awsRoleArn,
      })
    } else {
      createGcpMutation.mutate({
        cloud_account_id: cloudAccountId,
        credential_type: gcpCredentialType,
        service_account_email: gcpServiceAccountEmail || undefined,
        service_account_key: gcpCredentialType === 'gcp_service_account_key' ? gcpServiceAccountKey : undefined,
      })
    }
  }

  const downloadTemplate = async (type: 'cloudformation' | 'terraform-aws' | 'terraform-gcp' | 'gcloud') => {
    try {
      let content: string
      let filename: string

      switch (type) {
        case 'cloudformation':
          content = await credentialsApi.getAWSCloudFormationTemplate()
          filename = 'a13e-iam-role.yaml'
          break
        case 'terraform-aws':
          content = await credentialsApi.getAWSTerraformTemplate()
          filename = 'a13e-aws-role.tf'
          break
        case 'terraform-gcp':
          content = await credentialsApi.getGCPTerraformTemplate()
          filename = 'a13e-gcp-role.tf'
          break
        case 'gcloud':
          content = await credentialsApi.getGCPSetupScript()
          filename = 'a13e-gcp-setup.sh'
          break
      }

      const blob = new Blob([content], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to download template:', error)
    }
  }

  const renderStepIndicator = () => {
    const steps = [
      { key: 'instructions', label: 'Review Permissions' },
      { key: 'setup', label: 'Setup Access' },
      { key: 'credentials', label: 'Enter Credentials' },
      { key: 'validate', label: 'Validate' },
    ]

    const currentIndex = steps.findIndex(s => s.key === step)

    return (
      <div className="flex items-center justify-center mb-8">
        {steps.map((s, i) => (
          <div key={s.key} className="flex items-center">
            <div className={`flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium ${
              i < currentIndex
                ? 'bg-green-500 text-white'
                : i === currentIndex
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 text-gray-600'
            }`}>
              {i < currentIndex ? <Check className="w-4 h-4" /> : i + 1}
            </div>
            <span className={`ml-2 text-sm ${
              i === currentIndex ? 'text-gray-900 font-medium' : 'text-gray-500'
            }`}>
              {s.label}
            </span>
            {i < steps.length - 1 && (
              <ChevronRight className="w-4 h-4 mx-4 text-gray-400" />
            )}
          </div>
        ))}
      </div>
    )
  }

  const renderInstructionsStep = () => {
    if (instructionsLoading) {
      return (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
        </div>
      )
    }

    return (
      <div className="space-y-6">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start">
            <Shield className="w-5 h-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
            <div>
              <h4 className="font-medium text-blue-900">Least Privilege Access</h4>
              <p className="text-sm text-blue-700 mt-1">
                We request only the minimum permissions required to scan your security detections.
                No write access. No data modification. No billing access.
              </p>
            </div>
          </div>
        </div>

        <details className="border rounded-lg">
          <summary className="px-4 py-3 cursor-pointer font-medium text-gray-900 bg-gray-50 hover:bg-gray-100">
            Required Permissions ({instructions?.required_permissions.length || 0})
          </summary>
          <div className="divide-y max-h-64 overflow-y-auto">
            {instructions?.required_permissions.map((perm, i) => (
              <div key={i} className="p-3 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <code className="text-sm font-mono text-gray-800">
                    {provider === 'aws' ? perm.action : perm.permission}
                  </code>
                  <span className="text-xs text-gray-500">{perm.service}</span>
                </div>
                <p className="text-sm text-gray-600 mt-1">{perm.purpose}</p>
              </div>
            ))}
          </div>
        </details>

        {instructions?.not_requested && instructions.not_requested.length > 0 && (
          <div>
            <h4 className="font-medium text-gray-900 mb-3">What We Don't Access</h4>
            <div className="bg-gray-50 rounded-lg p-4">
              <ul className="text-sm text-gray-600 space-y-1">
                {instructions.not_requested.map((item, i) => (
                  <li key={i} className="flex items-center">
                    <X className="w-4 h-4 text-red-400 mr-2" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        <div className="flex justify-end">
          <button
            onClick={() => setStep('setup')}
            className="btn-primary flex items-center"
          >
            Continue
            <ChevronRight className="w-4 h-4 ml-2" />
          </button>
        </div>
      </div>
    )
  }

  // A13E's AWS Account ID - this would come from config in production
  const A13E_AWS_ACCOUNT_ID = '123456789012'

  const [setupMethod, setSetupMethod] = useState<'template' | 'manual'>('template')

  const renderSetupStep = () => {
    if (provider === 'aws') {
      return (
        <div className="space-y-4">
          {/* Required Information - ALWAYS visible at top */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h5 className="font-medium text-blue-900 mb-3 flex items-center">
              <Shield className="w-5 h-5 mr-2" />
              Required Information for Setup
            </h5>
            <div className="grid grid-cols-1 gap-3">
              <div className="bg-white rounded-lg p-3 border border-blue-100">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-blue-600 uppercase tracking-wide font-medium">A13E AWS Account ID</p>
                    <code className="text-lg font-mono text-gray-900">{A13E_AWS_ACCOUNT_ID}</code>
                  </div>
                  <button
                    onClick={() => copyToClipboard(A13E_AWS_ACCOUNT_ID, 'a13e_account')}
                    className="p-2 text-blue-600 hover:bg-blue-100 rounded-lg"
                  >
                    {copied === 'a13e_account' ? <Check className="w-5 h-5" /> : <Copy className="w-5 h-5" />}
                  </button>
                </div>
                <p className="text-xs text-gray-500 mt-1">Use this when setting up the trust relationship</p>
              </div>

              <div className="bg-white rounded-lg p-3 border border-blue-100">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-blue-600 uppercase tracking-wide font-medium">External ID (Security)</p>
                    {instructionsLoading ? (
                      <span className="text-lg font-mono text-gray-400">Loading...</span>
                    ) : instructions?.external_id ? (
                      <code className="text-lg font-mono text-gray-900">{instructions.external_id}</code>
                    ) : (
                      <span className="text-lg font-mono text-red-500">Error loading External ID</span>
                    )}
                  </div>
                  {instructions?.external_id && (
                    <button
                      onClick={() => copyToClipboard(instructions.external_id!, 'external_id')}
                      className="p-2 text-blue-600 hover:bg-blue-100 rounded-lg"
                    >
                      {copied === 'external_id' ? <Check className="w-5 h-5" /> : <Copy className="w-5 h-5" />}
                    </button>
                  )}
                </div>
                <p className="text-xs text-gray-500 mt-1">Prevents confused deputy attacks - required for IAM role</p>
              </div>
            </div>
          </div>

          {/* Prerequisites - collapsed by default */}
          <details className="border border-amber-200 rounded-lg bg-amber-50">
            <summary className="px-4 py-2 cursor-pointer font-medium text-amber-900 text-sm">
              Prerequisites - Permissions you need
            </summary>
            <div className="px-4 pb-3">
              <ul className="text-sm text-amber-800 space-y-1">
                <li>• <code className="bg-amber-100 px-1 rounded text-xs">iam:CreateRole</code>, <code className="bg-amber-100 px-1 rounded text-xs">iam:CreatePolicy</code>, <code className="bg-amber-100 px-1 rounded text-xs">iam:AttachRolePolicy</code></li>
                <li>• Or <code className="bg-amber-100 px-1 rounded text-xs">cloudformation:CreateStack</code> for template deployment</li>
              </ul>
            </div>
          </details>

          {/* Setup Method Tabs */}
          <div className="border rounded-lg overflow-hidden">
            <div className="flex border-b">
              <button
                onClick={() => setSetupMethod('template')}
                className={`flex-1 px-4 py-2 text-sm font-medium ${
                  setupMethod === 'template'
                    ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                Use Template (Recommended)
              </button>
              <button
                onClick={() => setSetupMethod('manual')}
                className={`flex-1 px-4 py-2 text-sm font-medium ${
                  setupMethod === 'manual'
                    ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                Manual Setup
              </button>
            </div>

            <div className="p-4">
              {setupMethod === 'template' ? (
                <div className="space-y-4">
                  <p className="text-sm text-gray-600">
                    Download a template that automatically creates the IAM role with correct permissions and trust policy.
                  </p>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      onClick={() => downloadTemplate('cloudformation')}
                      className="border-2 border-dashed border-gray-300 rounded-lg p-3 hover:border-blue-400 hover:bg-blue-50 transition-colors text-left"
                    >
                      <div className="flex items-center mb-1">
                        <FileCode className="w-4 h-4 text-orange-600 mr-2" />
                        <span className="font-medium text-sm">CloudFormation</span>
                      </div>
                      <p className="text-xs text-gray-500">Deploy via AWS Console</p>
                      <div className="mt-2 flex items-center text-blue-600 text-xs">
                        <Download className="w-3 h-3 mr-1" />
                        Download
                      </div>
                    </button>

                    <button
                      onClick={() => downloadTemplate('terraform-aws')}
                      className="border-2 border-dashed border-gray-300 rounded-lg p-3 hover:border-blue-400 hover:bg-blue-50 transition-colors text-left"
                    >
                      <div className="flex items-center mb-1">
                        <FileCode className="w-4 h-4 text-purple-600 mr-2" />
                        <span className="font-medium text-sm">Terraform</span>
                      </div>
                      <p className="text-xs text-gray-500">Infrastructure as Code</p>
                      <div className="mt-2 flex items-center text-blue-600 text-xs">
                        <Download className="w-3 h-3 mr-1" />
                        Download
                      </div>
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="bg-gray-50 rounded-lg p-3">
                    <h6 className="font-medium text-gray-900 mb-2 text-sm">Step-by-Step Instructions</h6>
                    <ol className="text-sm text-gray-700 space-y-2 list-decimal list-inside">
                      <li>Go to <strong>AWS IAM Console → Policies → Create policy</strong></li>
                      <li>Click <strong>JSON</strong> tab and paste the IAM Policy JSON (below)</li>
                      <li>Name the policy <strong>"A13E-DetectionScanner"</strong> and create it</li>
                      <li>Go to <strong>IAM → Roles → Create role</strong></li>
                      <li>Select <strong>"AWS account"</strong> as trusted entity type</li>
                      <li>Choose <strong>"Another AWS account"</strong> and enter: <code className="bg-gray-200 px-1 rounded">{A13E_AWS_ACCOUNT_ID}</code></li>
                      <li>Check <strong>"Require external ID"</strong> and enter the External ID shown above</li>
                      <li>Click <strong>Next</strong>, search for and attach <strong>"A13E-DetectionScanner"</strong> policy</li>
                      <li>Name the role <strong>"A13E-ReadOnly"</strong> and create it</li>
                      <li>Copy the <strong>Role ARN</strong> from the role summary page</li>
                    </ol>
                  </div>

                  {/* IAM Policy JSON */}
                  <div className="border rounded-lg">
                    <div className="px-3 py-2 bg-gray-100 border-b flex items-center justify-between">
                      <span className="font-medium text-sm text-gray-900">IAM Policy JSON</span>
                      <button
                        onClick={() => copyToClipboard(JSON.stringify(instructions?.iam_policy || {}, null, 2), 'iam_policy')}
                        className="text-blue-600 hover:text-blue-800 text-xs flex items-center"
                      >
                        {copied === 'iam_policy' ? (
                          <><Check className="w-3 h-3 mr-1" /> Copied!</>
                        ) : (
                          <><Copy className="w-3 h-3 mr-1" /> Copy</>
                        )}
                      </button>
                    </div>
                    <pre className="p-3 bg-gray-900 text-green-400 text-xs font-mono overflow-x-auto max-h-48 overflow-y-auto">
                      {JSON.stringify(instructions?.iam_policy || {}, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="flex justify-between pt-2">
            <button
              onClick={() => setStep('instructions')}
              className="btn-secondary flex items-center"
            >
              <ChevronLeft className="w-4 h-4 mr-2" />
              Back
            </button>
            <button
              onClick={() => setStep('credentials')}
              className="btn-primary flex items-center"
            >
              I've Created the Role
              <ChevronRight className="w-4 h-4 ml-2" />
            </button>
          </div>
        </div>
      )
    }

    // GCP Setup
    return (
      <div className="space-y-4">
        {/* Required Information for GCP */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h5 className="font-medium text-blue-900 mb-3 flex items-center">
            <Shield className="w-5 h-5 mr-2" />
            GCP Project Information
          </h5>
          <div className="bg-white rounded-lg p-3 border border-blue-100">
            <p className="text-xs text-blue-600 uppercase tracking-wide font-medium">Your Project ID</p>
            <code className="text-lg font-mono text-gray-900">{accountName.split(' ')[0] || 'your-project-id'}</code>
            <p className="text-xs text-gray-500 mt-1">This is the GCP project where you'll create the service account</p>
          </div>
        </div>

        {/* Prerequisites - collapsed by default */}
        <details className="border border-amber-200 rounded-lg bg-amber-50">
          <summary className="px-4 py-2 cursor-pointer font-medium text-amber-900 text-sm">
            Prerequisites - Permissions you need
          </summary>
          <div className="px-4 pb-3">
            <ul className="text-sm text-amber-800 space-y-1">
              <li>• <strong>Project Owner</strong> or <strong>IAM Admin</strong> role</li>
              <li>• <code className="bg-amber-100 px-1 rounded text-xs">iam.roles.create</code>, <code className="bg-amber-100 px-1 rounded text-xs">iam.serviceAccounts.create</code></li>
              <li>• <code className="bg-amber-100 px-1 rounded text-xs">gcloud</code> CLI installed (for script method)</li>
            </ul>
          </div>
        </details>

        {/* Recommendation note */}
        <div className="bg-green-50 border border-green-200 rounded-lg p-3">
          <div className="flex items-start">
            <Info className="w-4 h-4 text-green-600 mt-0.5 mr-2 flex-shrink-0" />
            <p className="text-sm text-green-800">
              <strong>Workload Identity Federation</strong> is recommended for production (no keys to manage).
            </p>
          </div>
        </div>

        {/* Setup Method Tabs */}
        <div className="border rounded-lg overflow-hidden">
          <div className="flex border-b">
            <button
              onClick={() => setSetupMethod('template')}
              className={`flex-1 px-4 py-2 text-sm font-medium ${
                setupMethod === 'template'
                  ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                  : 'text-gray-600 hover:bg-gray-50'
              }`}
            >
              Use Script (Recommended)
            </button>
            <button
              onClick={() => setSetupMethod('manual')}
              className={`flex-1 px-4 py-2 text-sm font-medium ${
                setupMethod === 'manual'
                  ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                  : 'text-gray-600 hover:bg-gray-50'
              }`}
            >
              Manual Setup
            </button>
          </div>

          <div className="p-4">
            {setupMethod === 'template' ? (
              <div className="space-y-4">
                <p className="text-sm text-gray-600">
                  Download a script that automatically creates the custom role and service account.
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => downloadTemplate('gcloud')}
                    className="border-2 border-dashed border-gray-300 rounded-lg p-3 hover:border-blue-400 hover:bg-blue-50 transition-colors text-left"
                  >
                    <div className="flex items-center mb-1">
                      <Terminal className="w-4 h-4 text-blue-600 mr-2" />
                      <span className="font-medium text-sm">gcloud Script</span>
                    </div>
                    <p className="text-xs text-gray-500">Run in Cloud Shell</p>
                    <div className="mt-2 flex items-center text-blue-600 text-xs">
                      <Download className="w-3 h-3 mr-1" />
                      Download
                    </div>
                  </button>

                  <button
                    onClick={() => downloadTemplate('terraform-gcp')}
                    className="border-2 border-dashed border-gray-300 rounded-lg p-3 hover:border-blue-400 hover:bg-blue-50 transition-colors text-left"
                  >
                    <div className="flex items-center mb-1">
                      <FileCode className="w-4 h-4 text-purple-600 mr-2" />
                      <span className="font-medium text-sm">Terraform</span>
                    </div>
                    <p className="text-xs text-gray-500">Infrastructure as Code</p>
                    <div className="mt-2 flex items-center text-blue-600 text-xs">
                      <Download className="w-3 h-3 mr-1" />
                      Download
                    </div>
                  </button>
                </div>

                {/* Inline gcloud commands preview */}
                {instructions?.gcloud_commands && instructions.gcloud_commands.length > 0 && (
                  <details className="border rounded-lg">
                    <summary className="px-3 py-2 cursor-pointer text-sm font-medium text-gray-700 bg-gray-50">
                      Preview gcloud commands
                    </summary>
                    <div className="p-3 bg-gray-900 rounded-b-lg">
                      <div className="flex justify-end mb-2">
                        <button
                          onClick={() => copyToClipboard(instructions.gcloud_commands!.join('\n'), 'gcloud')}
                          className="text-gray-400 hover:text-white text-xs flex items-center"
                        >
                          {copied === 'gcloud' ? <><Check className="w-3 h-3 mr-1" /> Copied</> : <><Copy className="w-3 h-3 mr-1" /> Copy</>}
                        </button>
                      </div>
                      <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap max-h-48 overflow-y-auto">
                        {instructions.gcloud_commands.join('\n')}
                      </pre>
                    </div>
                  </details>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                <div className="bg-gray-50 rounded-lg p-3">
                  <h6 className="font-medium text-gray-900 mb-2 text-sm">Step-by-Step Instructions</h6>
                  <ol className="text-sm text-gray-700 space-y-2 list-decimal list-inside">
                    <li>Go to <strong>GCP Console → IAM & Admin → Roles → Create Role</strong></li>
                    <li>Name it <strong>"A13E Detection Scanner"</strong></li>
                    <li>Add the permissions listed below (31 permissions total)</li>
                    <li>Go to <strong>IAM & Admin → Service Accounts → Create</strong></li>
                    <li>Name it <strong>"a13e-scanner"</strong></li>
                    <li>Grant the custom role to the service account</li>
                    <li>Copy the <strong>service account email</strong> (e.g., a13e-scanner@PROJECT.iam.gserviceaccount.com)</li>
                    <li>For SA Key auth: Go to <strong>Keys → Add Key → Create new key → JSON</strong></li>
                  </ol>
                </div>

                {/* Custom Role Permissions */}
                <div className="border rounded-lg">
                  <div className="px-3 py-2 bg-gray-100 border-b flex items-center justify-between">
                    <span className="font-medium text-sm text-gray-900">Required Permissions ({(instructions?.custom_role as { includedPermissions?: string[] })?.includedPermissions?.length || 0})</span>
                    <button
                      onClick={() => {
                        const perms = (instructions?.custom_role as { includedPermissions?: string[] })?.includedPermissions?.join('\n') || ''
                        copyToClipboard(perms, 'gcp_role')
                      }}
                      className="text-blue-600 hover:text-blue-800 text-xs flex items-center"
                    >
                      {copied === 'gcp_role' ? <><Check className="w-3 h-3 mr-1" /> Copied!</> : <><Copy className="w-3 h-3 mr-1" /> Copy</>}
                    </button>
                  </div>
                  <pre className="p-3 bg-gray-900 text-green-400 text-xs font-mono overflow-x-auto max-h-48 overflow-y-auto">
                    {(instructions?.custom_role as { includedPermissions?: string[] })?.includedPermissions?.join('\n') || 'Loading...'}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="flex justify-between pt-2">
          <button
            onClick={() => setStep('instructions')}
            className="btn-secondary flex items-center"
          >
            <ChevronLeft className="w-4 h-4 mr-2" />
            Back
          </button>
          <button
            onClick={() => setStep('credentials')}
            className="btn-primary flex items-center"
          >
            I've Created the Service Account
            <ChevronRight className="w-4 h-4 ml-2" />
          </button>
        </div>
      </div>
    )
  }

  const renderCredentialsStep = () => {
    if (provider === 'aws') {
      return (
        <div className="space-y-6">
          <div>
            <h4 className="font-medium text-gray-900 mb-3">Enter AWS Role ARN</h4>
            <p className="text-sm text-gray-600 mb-4">
              Provide the ARN of the IAM role you created. We'll use this to assume the role and scan your account.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              IAM Role ARN
            </label>
            <input
              type="text"
              value={awsRoleArn}
              onChange={(e) => setAwsRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/A13E-ReadOnly"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
            />
            <p className="text-xs text-gray-500 mt-1">
              Format: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
            </p>
          </div>

          {createAwsMutation.error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center">
                <AlertCircle className="w-5 h-5 text-red-600 mr-2" />
                <span className="text-red-800">
                  {(createAwsMutation.error as Error).message || 'Failed to save credentials'}
                </span>
              </div>
            </div>
          )}

          <div className="flex justify-between">
            <button
              onClick={() => setStep('setup')}
              className="btn-secondary flex items-center"
            >
              <ChevronLeft className="w-4 h-4 mr-2" />
              Back
            </button>
            <button
              onClick={handleSubmitCredentials}
              disabled={!awsRoleArn || createAwsMutation.isPending}
              className="btn-primary flex items-center disabled:opacity-50"
            >
              {createAwsMutation.isPending ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  Continue
                  <ChevronRight className="w-4 h-4 ml-2" />
                </>
              )}
            </button>
          </div>
        </div>
      )
    }

    // GCP Credentials
    return (
      <div className="space-y-6">
        <div>
          <h4 className="font-medium text-gray-900 mb-3">Enter GCP Credentials</h4>
          <p className="text-sm text-gray-600 mb-4">
            Provide the service account details for A13E to access your GCP project.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Authentication Method
          </label>
          <div className="grid grid-cols-2 gap-4">
            <button
              onClick={() => setGcpCredentialType('gcp_workload_identity')}
              className={`border-2 rounded-lg p-4 text-left transition-colors ${
                gcpCredentialType === 'gcp_workload_identity'
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="font-medium">Workload Identity</div>
              <p className="text-sm text-gray-600 mt-1">Keyless, recommended for production</p>
            </button>
            <button
              onClick={() => setGcpCredentialType('gcp_service_account_key')}
              className={`border-2 rounded-lg p-4 text-left transition-colors ${
                gcpCredentialType === 'gcp_service_account_key'
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="font-medium">Service Account Key</div>
              <p className="text-sm text-gray-600 mt-1">JSON key file (encrypted at rest)</p>
            </button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Service Account Email
          </label>
          <input
            type="email"
            value={gcpServiceAccountEmail}
            onChange={(e) => setGcpServiceAccountEmail(e.target.value)}
            placeholder="a13e-scanner@my-project.iam.gserviceaccount.com"
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
          />
        </div>

        {gcpCredentialType === 'gcp_service_account_key' && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Service Account Key (JSON)
            </label>
            <textarea
              value={gcpServiceAccountKey}
              onChange={(e) => setGcpServiceAccountKey(e.target.value)}
              placeholder='{"type": "service_account", "project_id": "...", ...}'
              rows={6}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-xs"
            />
            <p className="text-xs text-gray-500 mt-1">
              Your key will be encrypted using AES-256 before storage.
            </p>
          </div>
        )}

        {createGcpMutation.error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex items-center">
              <AlertCircle className="w-5 h-5 text-red-600 mr-2" />
              <span className="text-red-800">
                {(createGcpMutation.error as Error).message || 'Failed to save credentials'}
              </span>
            </div>
          </div>
        )}

        <div className="flex justify-between">
          <button
            onClick={() => setStep('setup')}
            className="btn-secondary flex items-center"
          >
            <ChevronLeft className="w-4 h-4 mr-2" />
            Back
          </button>
          <button
            onClick={handleSubmitCredentials}
            disabled={!gcpServiceAccountEmail || (gcpCredentialType === 'gcp_service_account_key' && !gcpServiceAccountKey) || createGcpMutation.isPending}
            className="btn-primary flex items-center disabled:opacity-50"
          >
            {createGcpMutation.isPending ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                Continue
                <ChevronRight className="w-4 h-4 ml-2" />
              </>
            )}
          </button>
        </div>
      </div>
    )
  }

  const renderValidateStep = () => {
    const credential = existingCredential
    const validation = validateMutation.data

    return (
      <div className="space-y-6">
        <div>
          <h4 className="font-medium text-gray-900 mb-3">Validate Connection</h4>
          <p className="text-sm text-gray-600 mb-4">
            We'll test the connection and verify all required permissions are granted.
          </p>
        </div>

        {credential && (
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="font-medium text-gray-900">Credential Status</span>
              <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                credential.status === 'valid'
                  ? 'bg-green-100 text-green-800'
                  : credential.status === 'pending'
                  ? 'bg-yellow-100 text-yellow-800'
                  : 'bg-red-100 text-red-800'
              }`}>
                {credential.status.charAt(0).toUpperCase() + credential.status.slice(1)}
              </span>
            </div>
            <div className="text-sm text-gray-600 space-y-1">
              <div>Type: <code className="bg-gray-100 px-1 rounded">{credential.credential_type}</code></div>
              {credential.aws_role_arn && (
                <div>Role: <code className="bg-gray-100 px-1 rounded text-xs">{credential.aws_role_arn}</code></div>
              )}
              {credential.gcp_service_account_email && (
                <div>Service Account: <code className="bg-gray-100 px-1 rounded text-xs">{credential.gcp_service_account_email}</code></div>
              )}
            </div>
          </div>
        )}

        {validation && (
          <div className={`rounded-lg p-4 ${
            validation.status === 'valid'
              ? 'bg-green-50 border border-green-200'
              : 'bg-red-50 border border-red-200'
          }`}>
            <div className="flex items-center mb-3">
              {validation.status === 'valid' ? (
                <CheckCircle2 className="w-5 h-5 text-green-600 mr-2" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-600 mr-2" />
              )}
              <span className={`font-medium ${
                validation.status === 'valid' ? 'text-green-900' : 'text-red-900'
              }`}>
                {validation.message}
              </span>
            </div>

            {validation.granted_permissions.length > 0 && (
              <div className="mb-3">
                <div className="text-sm font-medium text-gray-700 mb-1">Granted Permissions ({validation.granted_permissions.length})</div>
                <div className="flex flex-wrap gap-1">
                  {validation.granted_permissions.slice(0, 10).map((perm, i) => (
                    <span key={i} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-green-100 text-green-800">
                      <Check className="w-3 h-3 mr-1" />
                      {perm}
                    </span>
                  ))}
                  {validation.granted_permissions.length > 10 && (
                    <span className="text-xs text-gray-500">+{validation.granted_permissions.length - 10} more</span>
                  )}
                </div>
              </div>
            )}

            {validation.missing_permissions.length > 0 && (
              <div>
                <div className="text-sm font-medium text-red-700 mb-1">Missing Permissions ({validation.missing_permissions.length})</div>
                <div className="flex flex-wrap gap-1">
                  {validation.missing_permissions.map((perm, i) => (
                    <span key={i} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-red-100 text-red-800">
                      <X className="w-3 h-3 mr-1" />
                      {perm}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {validateMutation.error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex items-center">
              <AlertCircle className="w-5 h-5 text-red-600 mr-2" />
              <span className="text-red-800">
                {(validateMutation.error as Error).message || 'Validation failed'}
              </span>
            </div>
          </div>
        )}

        <div className="flex justify-between">
          <button
            onClick={() => setStep('credentials')}
            className="btn-secondary flex items-center"
          >
            <ChevronLeft className="w-4 h-4 mr-2" />
            Back
          </button>
          <div className="flex space-x-3">
            {validation?.status !== 'valid' && (
              <button
                onClick={() => validateMutation.mutate()}
                disabled={validateMutation.isPending}
                className="btn-secondary flex items-center"
              >
                {validateMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Validating...
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4 mr-2" />
                    Validate Connection
                  </>
                )}
              </button>
            )}
            {validation?.status === 'valid' && (
              <button
                onClick={onSuccess}
                className="btn-primary flex items-center"
              >
                <CheckCircle2 className="w-4 h-4 mr-2" />
                Done
              </button>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">
              Connect {provider.toUpperCase()} Account
            </h2>
            <p className="text-sm text-gray-500">{accountName}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto" style={{ maxHeight: 'calc(90vh - 80px)' }}>
          {renderStepIndicator()}

          {step === 'instructions' && renderInstructionsStep()}
          {step === 'setup' && renderSetupStep()}
          {step === 'credentials' && renderCredentialsStep()}
          {step === 'validate' && renderValidateStep()}
        </div>
      </div>
    </div>
  )
}
