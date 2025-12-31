import { useState } from 'react'
import { useParams, Link } from 'react-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Building2,
  ChevronLeft,
  RefreshCw,
  BarChart3,
  Users,
  Shield,
  AlertTriangle,
  Loader2,
} from 'lucide-react'
import {
  cloudOrganizationsApi,
  orgCoverageApi,
} from '../services/organizationsApi'

export default function OrganizationDashboard() {
  const { orgId } = useParams<{ orgId: string }>()
  const queryClient = useQueryClient()
  const [coverageView, setCoverageView] = useState<'union' | 'minimum'>('union')

  // Fetch organisation details
  const { data: organization, isLoading: orgLoading } = useQuery({
    queryKey: ['cloud-organization', orgId],
    queryFn: () => cloudOrganizationsApi.get(orgId!),
    enabled: !!orgId,
  })

  // Fetch organisation coverage
  const { data: coverage, isLoading: coverageLoading } = useQuery({
    queryKey: ['org-coverage', orgId],
    queryFn: () => orgCoverageApi.get(orgId!),
    enabled: !!orgId,
    retry: false,
  })

  const calculateCoverageMutation = useMutation({
    mutationFn: () => orgCoverageApi.calculate(orgId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['org-coverage', orgId] })
    },
  })

  if (orgLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
      </div>
    )
  }

  if (!organization) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h2 className="text-lg font-medium text-white">
          Organisation not found
        </h2>
        <Link to="/organizations" className="text-blue-600 hover:underline mt-2">
          Back to organisations
        </Link>
      </div>
    )
  }

  const providerColor =
    organization.provider === 'gcp'
      ? 'bg-blue-900/30 text-blue-400'
      : 'bg-orange-900/30 text-orange-400'

  const currentCoverage =
    coverageView === 'union'
      ? coverage?.union_coverage_percent
      : coverage?.minimum_coverage_percent

  const currentCoveredTechniques =
    coverageView === 'union'
      ? coverage?.union_covered_techniques
      : coverage?.minimum_covered_techniques

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <Link
          to="/organizations"
          className="text-gray-400 hover:text-white flex items-center mb-4"
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Back to Organisations
        </Link>

        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <div className={`p-3 rounded-lg ${providerColor}`}>
              <Building2 className="h-8 w-8" />
            </div>
            <div className="ml-4">
              <h1 className="text-2xl font-bold text-white">
                {organization.name}
              </h1>
              <p className="text-gray-400">
                {organization.provider.toUpperCase()} Organisation{' '}
                {organization.cloud_org_id}
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => calculateCoverageMutation.mutate()}
              disabled={calculateCoverageMutation.isPending}
              className="btn-secondary flex items-center"
            >
              <RefreshCw
                className={`h-4 w-4 mr-2 ${
                  calculateCoverageMutation.isPending ? 'animate-spin' : ''
                }`}
              />
              Refresh Coverage
            </button>
            <Link
              to={`/organizations/${orgId}/members`}
              className="btn-primary flex items-center"
            >
              <Users className="h-4 w-4 mr-2" />
              Manage Accounts
            </Link>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-6 mb-8">
        <StatCard
          icon={Users}
          label="Connected Accounts"
          value={`${organization.total_accounts_connected}/${organization.total_accounts_discovered}`}
          subtext="accounts connected"
        />
        <StatCard
          icon={Shield}
          label="Org Detections"
          value={coverage?.org_detection_count ?? '-'}
          subtext="org-level controls"
        />
        <StatCard
          icon={BarChart3}
          label="Avg Coverage"
          value={
            coverage?.average_coverage_percent
              ? `${coverage.average_coverage_percent.toFixed(1)}%`
              : '-'
          }
          subtext="across all accounts"
        />
        <StatCard
          icon={Shield}
          label="Org Techniques"
          value={coverage?.org_covered_techniques ?? '-'}
          subtext="covered by org controls"
        />
      </div>

      {/* Coverage Section */}
      {coverageLoading ? (
        <div className="card flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
        </div>
      ) : coverage ? (
        <div className="space-y-6">
          {/* Coverage View Toggle */}
          <div className="card">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold">Organisation Coverage</h2>
              <div className="flex bg-gray-700/30 rounded-lg p-1">
                <button
                  onClick={() => setCoverageView('union')}
                  className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                    coverageView === 'union'
                      ? 'bg-gray-700 shadow-sm text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  Any Account (Union)
                </button>
                <button
                  onClick={() => setCoverageView('minimum')}
                  className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                    coverageView === 'minimum'
                      ? 'bg-gray-700 shadow-sm text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  All Accounts (Minimum)
                </button>
              </div>
            </div>

            <div className="flex items-center justify-center">
              <OrgCoverageGauge
                percent={currentCoverage ?? 0}
                coveredTechniques={currentCoveredTechniques ?? 0}
                totalTechniques={coverage.total_techniques}
                viewType={coverageView}
              />
            </div>

            <div className="mt-6 text-center text-sm text-gray-400">
              {coverageView === 'union' ? (
                <p>
                  <strong>{coverage.union_covered_techniques}</strong> techniques
                  are covered in at least one account
                </p>
              ) : (
                <p>
                  <strong>{coverage.minimum_covered_techniques}</strong>{' '}
                  techniques are covered across ALL accounts
                </p>
              )}
            </div>
          </div>

          {/* Per-Account Coverage */}
          {coverage.per_account_coverage &&
            coverage.per_account_coverage.length > 0 && (
              <div className="card">
                <h2 className="text-lg font-semibold mb-4">
                  Per-Account Coverage
                </h2>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="text-left text-sm text-gray-400 border-b border-gray-700">
                        <th className="pb-3 font-medium">Account</th>
                        <th className="pb-3 font-medium">Account ID</th>
                        <th className="pb-3 font-medium text-right">Coverage</th>
                        <th className="pb-3 font-medium text-right">
                          Techniques
                        </th>
                        <th className="pb-3 font-medium"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {coverage.per_account_coverage.map((account) => (
                        <tr
                          key={account.cloud_account_id}
                          className="border-b border-gray-700 last:border-0 hover:bg-gray-700"
                        >
                          <td className="py-3 font-medium">
                            {account.account_name}
                          </td>
                          <td className="py-3 text-gray-400 font-mono text-sm">
                            {account.account_id}
                          </td>
                          <td className="py-3 text-right">
                            <CoverageBar percent={account.coverage_percent} />
                          </td>
                          <td className="py-3 text-right text-gray-400">
                            {account.covered_techniques}/
                            {account.total_techniques}
                          </td>
                          <td className="py-3 text-right">
                            <Link
                              to={`/coverage?account=${account.cloud_account_id}`}
                              className="text-blue-600 hover:underline text-sm"
                            >
                              View &rarr;
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

          {/* Tactic Coverage */}
          {coverage.tactic_coverage && coverage.tactic_coverage.length > 0 && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">
                Coverage by Tactic
              </h2>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                {coverage.tactic_coverage.map((tactic) => (
                  <div
                    key={tactic.tactic_id}
                    className="p-4 bg-gray-700/30 rounded-lg"
                  >
                    <div className="text-sm font-medium text-gray-400 mb-2">
                      {tactic.tactic_name}
                    </div>
                    <div className="flex items-end justify-between">
                      <div className="text-2xl font-bold text-white">
                        {coverageView === 'union'
                          ? tactic.union_percent.toFixed(0)
                          : tactic.minimum_percent.toFixed(0)}
                        %
                      </div>
                      <div className="text-xs text-gray-400">
                        {coverageView === 'union'
                          ? tactic.union_covered
                          : tactic.minimum_covered}
                        /{tactic.total_techniques}
                      </div>
                    </div>
                    <div className="mt-2 h-2 bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-600 rounded-full"
                        style={{
                          width: `${
                            coverageView === 'union'
                              ? tactic.union_percent
                              : tactic.minimum_percent
                          }%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="card text-center py-12">
          <BarChart3 className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h2 className="text-lg font-medium text-white mb-2">
            No coverage data yet
          </h2>
          <p className="text-gray-400 mb-4">
            Connect and scan accounts to see aggregate coverage.
          </p>
          <button
            onClick={() => calculateCoverageMutation.mutate()}
            disabled={calculateCoverageMutation.isPending}
            className="btn-primary"
          >
            Calculate Coverage
          </button>
        </div>
      )}
    </div>
  )
}

// Stat Card Component
function StatCard({
  icon: Icon,
  label,
  value,
  subtext,
}: {
  icon: React.ElementType
  label: string
  value: string | number
  subtext: string
}) {
  return (
    <div className="card">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-gray-400">{label}</span>
        <Icon className="h-5 w-5 text-gray-400" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-sm text-gray-400">{subtext}</div>
    </div>
  )
}

// Coverage Gauge Component
function OrgCoverageGauge({
  percent,
  coveredTechniques,
  totalTechniques,
  viewType,
}: {
  percent: number
  coveredTechniques: number
  totalTechniques: number
  viewType: 'union' | 'minimum'
}) {
  const circumference = 2 * Math.PI * 45
  const offset = circumference - (percent / 100) * circumference

  const getColor = () => {
    if (percent >= 70) return 'text-green-500'
    if (percent >= 40) return 'text-yellow-500'
    return 'text-red-500'
  }

  return (
    <div className="relative w-48 h-48">
      <svg className="w-48 h-48 transform -rotate-90">
        <circle
          cx="96"
          cy="96"
          r="45"
          stroke="currentColor"
          strokeWidth="10"
          fill="transparent"
          className="text-gray-200"
        />
        <circle
          cx="96"
          cy="96"
          r="45"
          stroke="currentColor"
          strokeWidth="10"
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className={getColor()}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold text-white">
          {percent.toFixed(0)}%
        </span>
        <span className="text-sm text-gray-400">
          {coveredTechniques}/{totalTechniques}
        </span>
        <span className="text-xs text-gray-400 mt-1">
          {viewType === 'union' ? 'Union' : 'Minimum'}
        </span>
      </div>
    </div>
  )
}

// Coverage Bar Component
function CoverageBar({ percent }: { percent: number }) {
  const getColor = () => {
    if (percent >= 70) return 'bg-green-500'
    if (percent >= 40) return 'bg-yellow-500'
    return 'bg-red-500'
  }

  return (
    <div className="flex items-center space-x-2">
      <div className="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${getColor()}`}
          style={{ width: `${percent}%` }}
        />
      </div>
      <span className="text-sm font-medium text-white w-12 text-right">
        {percent.toFixed(1)}%
      </span>
    </div>
  )
}
