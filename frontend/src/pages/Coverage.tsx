import { useQuery } from '@tanstack/react-query'
import { BarChart3, RefreshCw, Grid3X3, List, Shield, Target } from 'lucide-react'
import { useState } from 'react'
import { accountsApi, coverageApi } from '../services/api'
import TacticHeatmap from '../components/TacticHeatmap'
import CoverageGauge from '../components/CoverageGauge'
import MitreHeatmap from '../components/MitreHeatmap'
import { ComplianceCoverageContent } from '../components/compliance'

type ViewMode = 'heatmap' | 'tactics'
type CoverageTab = 'mitre' | 'compliance'

export default function Coverage() {
  const [viewMode, setViewMode] = useState<ViewMode>('heatmap')
  const [activeTab, setActiveTab] = useState<CoverageTab>('mitre')

  const { data: accounts } = useQuery({
    queryKey: ['accounts'],
    queryFn: accountsApi.list,
  })

  const firstAccount = accounts?.[0]

  const { data: coverage, isLoading, refetch } = useQuery({
    queryKey: ['coverage', firstAccount?.id],
    queryFn: () => coverageApi.get(firstAccount!.id),
    enabled: !!firstAccount,
  })

  const { data: techniques, isLoading: techniquesLoading } = useQuery({
    queryKey: ['techniques', firstAccount?.id],
    queryFn: () => coverageApi.getTechniques(firstAccount!.id),
    enabled: !!firstAccount,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!coverage) {
    return (
      <div className="text-center py-12 card">
        <BarChart3 className="mx-auto h-12 w-12 text-gray-400" />
        <h3 className="mt-2 text-lg font-medium text-gray-900">No coverage data</h3>
        <p className="mt-1 text-sm text-gray-500">
          Run a scan on your cloud accounts to calculate coverage.
        </p>
      </div>
    )
  }

  return (
    <div>
      {/* Tab Navigation */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('mitre')}
            className={`flex items-center px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'mitre'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Target className="w-4 h-4 mr-2" />
            MITRE ATT&CK
          </button>
          <button
            onClick={() => setActiveTab('compliance')}
            className={`flex items-center px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'compliance'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Shield className="w-4 h-4 mr-2" />
            Compliance
          </button>
        </nav>
      </div>

      {activeTab === 'compliance' && firstAccount ? (
        <div className="bg-gray-900 -mx-6 -mb-6 px-6 py-6 rounded-b-lg min-h-[600px]">
          <ComplianceCoverageContent accountId={firstAccount.id} />
        </div>
      ) : (
        <>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">MITRE ATT&CK Coverage</h1>
          <p className="text-gray-600">
            Version {coverage.mitre_version} - Last updated {new Date(coverage.created_at).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center space-x-2">
          {/* View Mode Toggle */}
          <div className="flex bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setViewMode('heatmap')}
              className={`flex items-center px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'heatmap'
                  ? 'bg-white text-gray-900 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <Grid3X3 className="h-4 w-4 mr-1.5" />
              Heatmap
            </button>
            <button
              onClick={() => setViewMode('tactics')}
              className={`flex items-center px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'tactics'
                  ? 'bg-white text-gray-900 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <List className="h-4 w-4 mr-1.5" />
              Tactics
            </button>
          </div>
          <button
            onClick={() => refetch()}
            className="btn-secondary flex items-center"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-green-600">{coverage.covered_techniques}</p>
          <p className="text-sm text-gray-500">Covered</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-yellow-600">{coverage.partial_techniques}</p>
          <p className="text-sm text-gray-500">Partial</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-gray-400">{coverage.uncovered_techniques}</p>
          <p className="text-sm text-gray-500">Uncovered</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-3xl font-bold text-blue-600">{coverage.total_techniques}</p>
          <p className="text-sm text-gray-500">Total Techniques</p>
        </div>
      </div>

      {/* Main Coverage View */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-6">Overall Score</h3>
          <CoverageGauge
            percent={coverage.coverage_percent}
            confidence={coverage.average_confidence}
          />
          <div className="mt-6 grid grid-cols-2 gap-4 text-center">
            <div className="p-3 bg-gray-50 rounded-lg">
              <p className="text-xl font-bold text-gray-900">{coverage.total_detections}</p>
              <p className="text-xs text-gray-500">Total Detections</p>
            </div>
            <div className="p-3 bg-gray-50 rounded-lg">
              <p className="text-xl font-bold text-gray-900">{coverage.mapped_detections}</p>
              <p className="text-xs text-gray-500">Mapped</p>
            </div>
          </div>
        </div>

        <div className="card lg:col-span-3">
          {viewMode === 'heatmap' ? (
            <>
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-gray-900">MITRE ATT&CK Cloud Technique Heatmap</h3>
                <p className="text-sm text-gray-500 mt-1">Coverage across 168 cloud-applicable techniques (IaaS, AWS, GCP)</p>
              </div>
              {techniquesLoading ? (
                <div className="flex items-center justify-center h-64">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </div>
              ) : techniques && techniques.length > 0 ? (
                <MitreHeatmap techniques={techniques} />
              ) : (
                <div className="text-center py-8 text-gray-500">
                  No technique data available
                </div>
              )}
            </>
          ) : (
            <>
              <h3 className="text-lg font-semibold text-gray-900 mb-6">Coverage by Tactic</h3>
              <TacticHeatmap tactics={coverage.tactic_coverage} />
            </>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="mt-6 card">
        <h4 className="text-sm font-medium text-gray-700 mb-3">Coverage Legend</h4>
        <div className="flex flex-wrap gap-6">
          <div className="flex items-center">
            <div className="w-4 h-4 bg-green-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Covered (&ge;60% confidence)</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-yellow-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Partial (40-60% confidence)</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-gray-300 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Uncovered (&lt;40% confidence)</span>
          </div>
        </div>
      </div>
        </>
      )}
    </div>
  )
}
