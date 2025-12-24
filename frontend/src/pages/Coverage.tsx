import { useQuery } from '@tanstack/react-query'
import { BarChart3, RefreshCw, Grid3X3, List, CheckCircle, AlertTriangle, XCircle, Shield } from 'lucide-react'
import { useState } from 'react'
import { coverageApi } from '../services/api'
import TacticHeatmap from '../components/TacticHeatmap'
import CoverageGauge from '../components/CoverageGauge'
import MitreHeatmap from '../components/MitreHeatmap'
import { TechniqueDetailModal } from '../components/coverage/TechniqueDetailModal'
import { useSelectedAccount } from '../hooks/useSelectedAccount'
import SecurityFunctionBreakdown from '../components/SecurityFunctionBreakdown'

type ViewMode = 'heatmap' | 'tactics'
type ModalType = 'covered' | 'partial' | 'uncovered' | 'total' | null

export default function Coverage() {
  const [viewMode, setViewMode] = useState<ViewMode>('heatmap')
  const [activeModal, setActiveModal] = useState<ModalType>(null)

  const { selectedAccount } = useSelectedAccount()

  const { data: coverage, isLoading, refetch } = useQuery({
    queryKey: ['coverage', selectedAccount?.id],
    queryFn: () => coverageApi.get(selectedAccount!.id),
    enabled: !!selectedAccount,
  })

  const { data: techniques, isLoading: techniquesLoading } = useQuery({
    queryKey: ['techniques', selectedAccount?.id],
    queryFn: () => coverageApi.getTechniques(selectedAccount!.id),
    enabled: !!selectedAccount,
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
        <h3 className="mt-2 text-lg font-medium text-white">No coverage data</h3>
        <p className="mt-1 text-sm text-gray-400">
          Run a scan on your cloud accounts to calculate coverage.
        </p>
      </div>
    )
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">MITRE ATT&CK Coverage</h1>
          <p className="text-gray-400">
            Version {coverage.mitre_version} - Last updated {new Date(coverage.created_at).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center space-x-2">
          {/* View Mode Toggle */}
          <div className="flex bg-gray-800 rounded-lg p-1">
            <button
              onClick={() => setViewMode('heatmap')}
              className={`flex items-center px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'heatmap'
                  ? 'bg-gray-600 text-white shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <Grid3X3 className="h-4 w-4 mr-1.5" />
              Heatmap
            </button>
            <button
              onClick={() => setViewMode('tactics')}
              className={`flex items-center px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'tactics'
                  ? 'bg-gray-600 text-white shadow-sm'
                  : 'text-gray-400 hover:text-white'
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

      {/* Summary Cards - Clickable */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <button
          onClick={() => setActiveModal('covered')}
          className="stat-card text-center hover:bg-gray-50 hover:shadow-md transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-center gap-2 mb-1">
            <CheckCircle className="w-5 h-5 text-green-500" />
          </div>
          <p className="text-3xl font-bold text-green-600">{coverage.covered_techniques}</p>
          <p className="text-sm text-gray-400">Covered</p>
          <p className="text-xs text-gray-400 mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
        <button
          onClick={() => setActiveModal('partial')}
          className="stat-card text-center hover:bg-gray-50 hover:shadow-md transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-center gap-2 mb-1">
            <AlertTriangle className="w-5 h-5 text-yellow-500" />
          </div>
          <p className="text-3xl font-bold text-yellow-600">{coverage.partial_techniques}</p>
          <p className="text-sm text-gray-400">Partial</p>
          <p className="text-xs text-gray-400 mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
        <button
          onClick={() => setActiveModal('uncovered')}
          className="stat-card text-center hover:bg-gray-50 hover:shadow-md transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-center gap-2 mb-1">
            <XCircle className="w-5 h-5 text-gray-400" />
          </div>
          <p className="text-3xl font-bold text-gray-400">{coverage.uncovered_techniques}</p>
          <p className="text-sm text-gray-400">Uncovered</p>
          <p className="text-xs text-gray-400 mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
        <button
          onClick={() => setActiveModal('total')}
          className="stat-card text-center hover:bg-gray-50 hover:shadow-md transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-center gap-2 mb-1">
            <Shield className="w-5 h-5 text-blue-400" />
          </div>
          <p className="text-3xl font-bold text-blue-600">{coverage.total_techniques}</p>
          <p className="text-sm text-gray-400">Total Techniques</p>
          <p className="text-xs text-gray-400 mt-1 opacity-0 group-hover:opacity-100 transition-opacity">Click for details</p>
        </button>
      </div>

      {/* Main Coverage View */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-6">Overall Score</h3>
          <CoverageGauge
            percent={coverage.coverage_percent}
            confidence={coverage.average_confidence}
          />
          <div className="mt-6 grid grid-cols-2 gap-4 text-center">
            <div className="p-3 bg-gray-700 rounded-lg">
              <p className="text-xl font-bold text-white">{coverage.total_detections}</p>
              <p className="text-xs text-gray-400">Total Detections</p>
            </div>
            <div className="p-3 bg-gray-700 rounded-lg">
              <p className="text-xl font-bold text-white">{coverage.mapped_detections}</p>
              <p className="text-xs text-gray-400">Mapped</p>
            </div>
          </div>

          {/* Security Function Breakdown */}
          {coverage.security_function_breakdown && (
            <div className="mt-6 p-4 bg-slate-800 rounded-lg">
              <SecurityFunctionBreakdown breakdown={coverage.security_function_breakdown} />
            </div>
          )}
        </div>

        <div className="card lg:col-span-3">
          {viewMode === 'heatmap' ? (
            <>
              <div className="mb-6">
                <h3 className="text-lg font-semibold text-white">MITRE ATT&CK Cloud Technique Heatmap</h3>
                <p className="text-sm text-gray-400 mt-1">Coverage across 168 cloud-applicable techniques (IaaS, AWS, GCP)</p>
              </div>
              {techniquesLoading ? (
                <div className="flex items-center justify-center h-64">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </div>
              ) : techniques && techniques.length > 0 ? (
                <MitreHeatmap techniques={techniques} />
              ) : (
                <div className="text-center py-8 text-gray-400">
                  No technique data available
                </div>
              )}
            </>
          ) : (
            <>
              <h3 className="text-lg font-semibold text-white mb-6">Coverage by Tactic</h3>
              <TacticHeatmap tactics={coverage.tactic_coverage} />
            </>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="mt-6 card">
        <h4 className="text-sm font-medium text-white mb-3">Coverage Legend</h4>
        <div className="flex flex-wrap gap-6">
          <div className="flex items-center">
            <div className="w-4 h-4 bg-green-500 rounded mr-2"></div>
            <span className="text-sm text-gray-400">Covered (&ge;60% confidence)</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-yellow-500 rounded mr-2"></div>
            <span className="text-sm text-gray-400">Partial (40-60% confidence)</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-gray-300 rounded mr-2"></div>
            <span className="text-sm text-gray-400">Uncovered (&lt;40% confidence)</span>
          </div>
        </div>
      </div>

      {/* Technique Detail Modal */}
      {activeModal && techniques && (
        <TechniqueDetailModal
          isOpen={!!activeModal}
          onClose={() => setActiveModal(null)}
          title={
            activeModal === 'covered' ? 'Covered Techniques' :
            activeModal === 'partial' ? 'Partial Techniques' :
            activeModal === 'uncovered' ? 'Uncovered Techniques' :
            'All Techniques'
          }
          description={
            activeModal === 'covered' ? 'Techniques with 60% or higher detection confidence. These have adequate detection coverage.' :
            activeModal === 'partial' ? 'Techniques with 40-60% detection confidence. Some detection exists but coverage could be improved.' :
            activeModal === 'uncovered' ? 'Techniques with less than 40% detection confidence. These need detection coverage to be implemented.' :
            'All MITRE ATT&CK cloud techniques and their current detection coverage status.'
          }
          techniques={
            activeModal === 'total'
              ? techniques
              : techniques.filter(t => t.status === activeModal)
          }
          variant={activeModal}
        />
      )}
    </div>
  )
}
