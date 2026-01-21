import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Globe, Search, ChevronDown, ChevronUp, RefreshCw, Info } from 'lucide-react'
import { regionsApi, RegionConfig, RegionScanMode } from '../services/api'

interface RegionSelectorProps {
  provider: 'aws' | 'gcp' | 'azure'
  accountId?: string
  value: RegionConfig
  onChange: (config: RegionConfig) => void
  disabled?: boolean
}

// Region groupings for better UX
const AWS_REGION_GROUPS: Record<string, string[]> = {
  'US': ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'],
  'Europe': ['eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-central-2', 'eu-north-1', 'eu-south-1', 'eu-south-2'],
  'Asia Pacific': ['ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-south-1', 'ap-south-2', 'ap-east-1'],
  'Americas': ['ca-central-1', 'ca-west-1', 'sa-east-1'],
  'Middle East & Africa': ['me-south-1', 'me-central-1', 'af-south-1', 'il-central-1'],
}

const GCP_REGION_GROUPS: Record<string, string[]> = {
  'US': ['us-central1', 'us-east1', 'us-east4', 'us-east5', 'us-south1', 'us-west1', 'us-west2', 'us-west3', 'us-west4'],
  'Europe': ['europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6', 'europe-west8', 'europe-west9', 'europe-west10', 'europe-west12', 'europe-north1', 'europe-central2', 'europe-southwest1'],
  'Asia Pacific': ['asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3', 'asia-south1', 'asia-south2', 'asia-southeast1', 'asia-southeast2'],
  'Australia': ['australia-southeast1', 'australia-southeast2'],
  'Americas': ['northamerica-northeast1', 'northamerica-northeast2', 'southamerica-east1', 'southamerica-west1'],
  'Middle East & Africa': ['me-west1', 'me-central1', 'me-central2', 'africa-south1'],
}

const AZURE_REGION_GROUPS: Record<string, string[]> = {
  'US': ['eastus', 'eastus2', 'centralus', 'northcentralus', 'southcentralus', 'westcentralus', 'westus', 'westus2', 'westus3'],
  'Europe': ['northeurope', 'westeurope', 'uksouth', 'ukwest', 'francecentral', 'francesouth', 'germanywestcentral', 'germanynorth', 'norwayeast', 'norwaywest', 'swedencentral', 'switzerlandnorth', 'switzerlandwest'],
  'Asia Pacific': ['eastasia', 'southeastasia', 'japaneast', 'japanwest', 'koreacentral', 'koreasouth', 'australiaeast', 'australiasoutheast', 'australiacentral', 'centralindia', 'southindia', 'westindia'],
  'Americas': ['canadacentral', 'canadaeast', 'brazilsouth', 'brazilsoutheast'],
  'Middle East & Africa': ['uaenorth', 'uaecentral', 'southafricanorth', 'southafricawest', 'qatarcentral'],
}

export default function RegionSelector({
  provider,
  accountId,
  value,
  onChange,
  disabled = false,
}: RegionSelectorProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['Europe', 'US']))

  // Fetch available regions
  const { data: availableRegions, isLoading: regionsLoading } = useQuery({
    queryKey: ['regions', provider],
    queryFn: () => regionsApi.getAvailable(provider),
    staleTime: 300000, // 5 minutes
  })

  // Auto-discover regions mutation
  const discoverMutation = useMutation({
    mutationFn: () => regionsApi.discover(accountId!),
    onSuccess: (data) => {
      onChange({
        ...value,
        mode: 'auto',
        discovered_regions: data.discovered_regions,
        auto_discovered_at: data.discovered_at,
      })
    },
  })

  const regionGroups = provider === 'aws' ? AWS_REGION_GROUPS : provider === 'gcp' ? GCP_REGION_GROUPS : AZURE_REGION_GROUPS
  const allRegions = availableRegions?.regions || []

  // Filter regions based on search
  const filteredRegions = searchTerm
    ? allRegions.filter(r => r.toLowerCase().includes(searchTerm.toLowerCase()))
    : allRegions

  // Get regions to display based on mode
  const getDisplayRegions = (): string[] => {
    switch (value.mode) {
      case 'all':
        return allRegions.filter(r => !value.excluded_regions?.includes(r))
      case 'auto':
        return value.discovered_regions || []
      case 'selected':
      default:
        return value.regions || []
    }
  }

  const displayRegions = getDisplayRegions()

  const handleModeChange = (mode: RegionScanMode) => {
    onChange({
      ...value,
      mode,
    })
  }

  const handleRegionToggle = (region: string) => {
    if (value.mode === 'all') {
      // In "all" mode, toggle exclusion
      const excluded = value.excluded_regions || []
      const newExcluded = excluded.includes(region)
        ? excluded.filter(r => r !== region)
        : [...excluded, region]
      onChange({
        ...value,
        excluded_regions: newExcluded,
      })
    } else {
      // In "selected" mode, toggle selection
      const regions = value.regions || []
      const newRegions = regions.includes(region)
        ? regions.filter(r => r !== region)
        : [...regions, region]
      onChange({
        ...value,
        regions: newRegions,
      })
    }
  }

  const toggleGroup = (group: string) => {
    const newExpanded = new Set(expandedGroups)
    if (newExpanded.has(group)) {
      newExpanded.delete(group)
    } else {
      newExpanded.add(group)
    }
    setExpandedGroups(newExpanded)
  }

  const selectAllInGroup = (group: string) => {
    const groupRegions = regionGroups[group] || []
    if (value.mode === 'selected') {
      const currentRegions = new Set(value.regions || [])
      groupRegions.forEach(r => currentRegions.add(r))
      onChange({
        ...value,
        regions: Array.from(currentRegions),
      })
    }
  }

  const deselectAllInGroup = (group: string) => {
    const groupRegions = new Set(regionGroups[group] || [])
    if (value.mode === 'selected') {
      onChange({
        ...value,
        regions: (value.regions || []).filter(r => !groupRegions.has(r)),
      })
    }
  }

  if (regionsLoading) {
    return (
      <div className="flex items-center text-gray-500 text-sm">
        <RefreshCw className="h-4 w-4 animate-spin mr-2" />
        Loading regions...
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Mode Selector */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Region Scanning Mode
        </label>
        <div className="flex space-x-2">
          <button
            type="button"
            onClick={() => handleModeChange('selected')}
            disabled={disabled}
            className={`px-4 py-2 text-sm rounded-lg border transition-colors ${
              value.mode === 'selected'
                ? 'bg-blue-50 border-blue-500 text-blue-700'
                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
            } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            Selected Regions
          </button>
          <button
            type="button"
            onClick={() => handleModeChange('all')}
            disabled={disabled}
            className={`px-4 py-2 text-sm rounded-lg border transition-colors ${
              value.mode === 'all'
                ? 'bg-blue-50 border-blue-500 text-blue-700'
                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
            } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            All Regions
          </button>
          {accountId && (
            <button
              type="button"
              onClick={() => handleModeChange('auto')}
              disabled={disabled}
              className={`px-4 py-2 text-sm rounded-lg border transition-colors ${
                value.mode === 'auto'
                  ? 'bg-blue-50 border-blue-500 text-blue-700'
                  : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
              } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              Auto-Discover
            </button>
          )}
        </div>
      </div>

      {/* Mode Description */}
      <div className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">
        {value.mode === 'selected' && (
          <div className="flex items-start">
            <Info className="h-4 w-4 mr-2 mt-0.5 text-blue-500" />
            <span>Scan only the regions you explicitly select below.</span>
          </div>
        )}
        {value.mode === 'all' && (
          <div className="flex items-start">
            <Info className="h-4 w-4 mr-2 mt-0.5 text-blue-500" />
            <span>Scan all available regions. You can exclude specific regions below.</span>
          </div>
        )}
        {value.mode === 'auto' && (
          <div className="flex items-start">
            <Info className="h-4 w-4 mr-2 mt-0.5 text-blue-500" />
            <span>
              Automatically discover and scan regions with active resources.
              {value.auto_discovered_at && (
                <span className="block text-xs text-gray-500 mt-1">
                  Last discovered: {new Date(value.auto_discovered_at).toLocaleString()}
                </span>
              )}
            </span>
          </div>
        )}
      </div>

      {/* Auto-discover button */}
      {value.mode === 'auto' && accountId && (
        <button
          type="button"
          onClick={() => discoverMutation.mutate()}
          disabled={disabled || discoverMutation.isPending}
          className="flex items-center px-4 py-2 text-sm bg-purple-50 text-purple-900 border border-purple-200 rounded-lg hover:bg-purple-100 disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${discoverMutation.isPending ? 'animate-spin' : ''}`} />
          {discoverMutation.isPending ? 'Discovering...' : 'Discover Active Regions'}
        </button>
      )}

      {/* Region Summary */}
      <div className="flex items-center justify-between">
        <div className="flex items-center text-sm text-gray-600">
          <Globe className="h-4 w-4 mr-2" />
          {displayRegions.length} region{displayRegions.length !== 1 ? 's' : ''} selected
          {value.mode === 'all' && value.excluded_regions && value.excluded_regions.length > 0 && (
            <span className="ml-2 text-yellow-600">
              ({value.excluded_regions.length} excluded)
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-sm text-blue-600 hover:text-blue-700 flex items-center"
        >
          {isExpanded ? (
            <>
              <ChevronUp className="h-4 w-4 mr-1" />
              Collapse
            </>
          ) : (
            <>
              <ChevronDown className="h-4 w-4 mr-1" />
              {value.mode === 'all' ? 'Manage Exclusions' : 'Select Regions'}
            </>
          )}
        </button>
      </div>

      {/* Region Selection Panel */}
      {isExpanded && value.mode !== 'auto' && (
        <div className="border rounded-lg overflow-hidden">
          {/* Search */}
          <div className="p-3 border-b bg-gray-50">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search regions..."
                className="w-full pl-10 pr-4 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          {/* Region Groups */}
          <div className="max-h-80 overflow-y-auto">
            {searchTerm ? (
              // Flat list when searching
              <div className="p-2 space-y-1">
                {filteredRegions.map((region) => {
                  const isSelected = value.mode === 'all'
                    ? !value.excluded_regions?.includes(region)
                    : value.regions?.includes(region)
                  return (
                    <label
                      key={region}
                      className="flex items-center p-2 rounded-sm hover:bg-gray-50 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => handleRegionToggle(region)}
                        disabled={disabled}
                        className="h-4 w-4 text-blue-600 rounded-sm border-gray-300 focus:ring-blue-500"
                      />
                      <span className="ml-3 text-sm text-gray-700">{region}</span>
                    </label>
                  )
                })}
              </div>
            ) : (
              // Grouped view
              <div className="divide-y">
                {Object.entries(regionGroups).map(([group, regions]) => (
                  <div key={group}>
                    <button
                      type="button"
                      onClick={() => toggleGroup(group)}
                      className="w-full flex items-center justify-between p-3 bg-gray-50 hover:bg-gray-100"
                    >
                      <span className="font-medium text-gray-700">{group}</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-gray-500">
                          {regions.filter(r =>
                            value.mode === 'all'
                              ? !value.excluded_regions?.includes(r)
                              : value.regions?.includes(r)
                          ).length}/{regions.length}
                        </span>
                        {expandedGroups.has(group) ? (
                          <ChevronUp className="h-4 w-4 text-gray-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-gray-400" />
                        )}
                      </div>
                    </button>
                    {expandedGroups.has(group) && (
                      <div className="p-2 space-y-1">
                        <div className="flex space-x-2 mb-2 px-2">
                          <button
                            type="button"
                            onClick={() => selectAllInGroup(group)}
                            disabled={disabled || value.mode === 'all'}
                            className="text-xs text-blue-600 hover:text-blue-700 disabled:opacity-50"
                          >
                            Select all
                          </button>
                          <button
                            type="button"
                            onClick={() => deselectAllInGroup(group)}
                            disabled={disabled || value.mode === 'all'}
                            className="text-xs text-gray-600 hover:text-gray-700 disabled:opacity-50"
                          >
                            Deselect all
                          </button>
                        </div>
                        {regions.map((region) => {
                          const isSelected = value.mode === 'all'
                            ? !value.excluded_regions?.includes(region)
                            : value.regions?.includes(region)
                          return (
                            <label
                              key={region}
                              className="flex items-center p-2 rounded-sm hover:bg-gray-50 cursor-pointer"
                            >
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => handleRegionToggle(region)}
                                disabled={disabled}
                                className="h-4 w-4 text-blue-600 rounded-sm border-gray-300 focus:ring-blue-500"
                              />
                              <span className="ml-3 text-sm text-gray-700">{region}</span>
                            </label>
                          )
                        })}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Discovered regions display for auto mode */}
      {isExpanded && value.mode === 'auto' && displayRegions.length > 0 && (
        <div className="border rounded-lg p-4">
          <h4 className="text-sm font-medium text-gray-700 mb-2">Discovered Regions</h4>
          <div className="flex flex-wrap gap-2">
            {displayRegions.map((region) => (
              <span
                key={region}
                className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full"
              >
                {region}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
