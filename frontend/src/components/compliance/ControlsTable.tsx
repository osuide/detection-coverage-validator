/**
 * Controls Table Component.
 *
 * Displays a table of control gaps with their coverage status
 * and cloud applicability information.
 */

import { AlertTriangle, Cloud, Building, Info } from 'lucide-react'
import { ControlGapItem, CloudApplicability } from '../../services/complianceApi'

interface ControlsTableProps {
  controls: ControlGapItem[]
}

// Cloud applicability display configuration
const applicabilityConfig: Record<
  CloudApplicability,
  { label: string; colour: string; icon: React.ReactNode; description: string }
> = {
  highly_relevant: {
    label: 'Cloud',
    colour: 'bg-green-900/50 text-green-300 border-green-700',
    icon: <Cloud className="w-3 h-3" />,
    description: 'Directly applicable to cloud environments',
  },
  moderately_relevant: {
    label: 'Partial',
    colour: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
    icon: <Cloud className="w-3 h-3" />,
    description: 'Partially applicable to cloud',
  },
  informational: {
    label: 'Info',
    colour: 'bg-blue-900/50 text-blue-300 border-blue-700',
    icon: <Info className="w-3 h-3" />,
    description: 'Informational - may require adaptation',
  },
  provider_responsibility: {
    label: 'Provider',
    colour: 'bg-purple-900/50 text-purple-300 border-purple-700',
    icon: <Building className="w-3 h-3" />,
    description: 'Managed by cloud provider',
  },
}

export function ControlsTable({ controls }: ControlsTableProps) {
  const getPriorityBadge = (priority: string | null) => {
    if (!priority) return null

    const styles: Record<string, string> = {
      P1: 'bg-red-900/50 text-red-300 border-red-700',
      P2: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
      P3: 'bg-blue-900/50 text-blue-300 border-blue-700',
    }

    return (
      <span
        className={`px-2 py-0.5 text-xs font-medium rounded border ${
          styles[priority] || 'bg-gray-700 text-gray-300 border-gray-600'
        }`}
      >
        {priority}
      </span>
    )
  }

  const getApplicabilityBadge = (applicability: CloudApplicability | undefined) => {
    if (!applicability) return null
    const config = applicabilityConfig[applicability]
    return (
      <span
        className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded border ${config.colour}`}
        title={config.description}
      >
        {config.icon}
        {config.label}
      </span>
    )
  }

  const getCoverageColour = (percent: number) => {
    if (percent >= 0.8) return 'text-green-400'
    if (percent >= 0.4) return 'text-yellow-400'
    return 'text-red-400'
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="text-left text-xs text-gray-400 uppercase tracking-wider border-b border-gray-700">
            <th className="pb-3 pr-4">Control</th>
            <th className="pb-3 pr-4">Family</th>
            <th className="pb-3 pr-4">Cloud</th>
            <th className="pb-3 pr-4">Priority</th>
            <th className="pb-3 pr-4">Coverage</th>
            <th className="pb-3">Cloud Services</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-700">
          {controls.map((control) => (
            <tr key={control.control_id} className="hover:bg-gray-700/30">
              <td className="py-3 pr-4">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0" />
                  <div>
                    <span className="text-white font-medium">{control.control_id}</span>
                    <p className="text-sm text-gray-400 truncate max-w-[200px]" title={control.control_name}>
                      {control.control_name}
                    </p>
                  </div>
                </div>
              </td>
              <td className="py-3 pr-4">
                <span className="text-sm text-gray-300">{control.control_family}</span>
              </td>
              <td className="py-3 pr-4">
                {getApplicabilityBadge(control.cloud_applicability)}
              </td>
              <td className="py-3 pr-4">
                {getPriorityBadge(control.priority)}
              </td>
              <td className="py-3 pr-4">
                <div className="flex items-center gap-2">
                  <div className="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${
                        control.coverage_percent >= 0.4 ? 'bg-yellow-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${control.coverage_percent * 100}%` }}
                    />
                  </div>
                  <span className={`text-sm ${getCoverageColour(control.coverage_percent)}`}>
                    {(control.coverage_percent * 100).toFixed(0)}%
                  </span>
                </div>
              </td>
              <td className="py-3">
                <div className="flex flex-wrap gap-1">
                  {control.cloud_context?.aws_services?.slice(0, 2).map((svc) => (
                    <span
                      key={svc}
                      className="px-2 py-0.5 text-xs bg-orange-900/50 text-orange-300 border border-orange-700 rounded"
                      title={`AWS: ${svc}`}
                    >
                      AWS {svc}
                    </span>
                  ))}
                  {control.cloud_context?.gcp_services?.slice(0, 2).map((svc) => (
                    <span
                      key={svc}
                      className="px-2 py-0.5 text-xs bg-blue-900/50 text-blue-300 border border-blue-700 rounded"
                      title={`GCP: ${svc}`}
                    >
                      GCP {svc}
                    </span>
                  ))}
                  {!control.cloud_context?.aws_services?.length &&
                    !control.cloud_context?.gcp_services?.length && (
                      <span className="text-xs text-gray-500 italic">
                        {control.cloud_applicability === 'provider_responsibility'
                          ? 'Managed by provider'
                          : control.cloud_applicability === 'informational'
                            ? 'Not cloud-specific'
                            : 'No services mapped'}
                      </span>
                    )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
