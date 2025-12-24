import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  Database, RefreshCw, ChevronLeft, Check, AlertCircle,
  Users, Target, Package, Link as LinkIcon, Clock,
  Calendar, ExternalLink, Search, ChevronUp, ChevronDown
} from 'lucide-react'
import { useAdminAuthStore } from '../../stores/adminAuthStore'
import {
  mitreApi,
  MitreStatus,
  MitreSyncHistory,
  ThreatGroupSummary,
  CampaignSummary,
} from '../../services/adminMitreApi'

type TabType = 'overview' | 'groups' | 'campaigns' | 'history'

export default function AdminMitreData() {
  const navigate = useNavigate()
  const { isAuthenticated, isInitialised } = useAdminAuthStore()

  const [status, setStatus] = useState<MitreStatus | null>(null)
  const [syncHistory, setSyncHistory] = useState<MitreSyncHistory[]>([])
  const [groups, setGroups] = useState<ThreatGroupSummary[]>([])
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [activeTab, setActiveTab] = useState<TabType>('overview')
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [campaignSearch, setCampaignSearch] = useState('')
  const [campaignSortBy, setCampaignSortBy] = useState<string>('last_seen')
  const [campaignSortOrder, setCampaignSortOrder] = useState<'asc' | 'desc'>('desc')

  // Redirect if not authenticated
  useEffect(() => {
    if (isInitialised && !isAuthenticated) {
      navigate('/admin/login')
    }
  }, [isAuthenticated, isInitialised, navigate])

  useEffect(() => {
    if (isAuthenticated) {
      fetchData()
    }
  }, [isAuthenticated])

  const fetchData = async () => {
    try {
      const [statusData, historyData] = await Promise.all([
        mitreApi.getStatus(),
        mitreApi.getSyncHistory(10),
      ])
      setStatus(statusData)
      setSyncHistory(historyData)
    } catch (error) {
      console.error('Failed to fetch MITRE data:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchGroups = async () => {
    try {
      const data = await mitreApi.getGroups(0, 100, searchQuery || undefined)
      setGroups(data.items)
    } catch (error) {
      console.error('Failed to fetch groups:', error)
    }
  }

  const fetchCampaigns = async () => {
    try {
      const data = await mitreApi.getCampaigns(
        0,
        100,
        campaignSearch || undefined,
        campaignSortBy,
        campaignSortOrder
      )
      setCampaigns(data.items)
    } catch (error) {
      console.error('Failed to fetch campaigns:', error)
    }
  }

  const handleCampaignSort = (field: string) => {
    if (campaignSortBy === field) {
      // Toggle sort order if clicking same column
      setCampaignSortOrder(campaignSortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      // New column, default to descending for dates, ascending for text
      setCampaignSortBy(field)
      setCampaignSortOrder(field === 'name' || field === 'external_id' ? 'asc' : 'desc')
    }
  }

  const SortIcon = ({ field }: { field: string }) => {
    if (campaignSortBy !== field) return null
    return campaignSortOrder === 'asc'
      ? <ChevronUp className="h-4 w-4 inline ml-1" />
      : <ChevronDown className="h-4 w-4 inline ml-1" />
  }

  useEffect(() => {
    if (activeTab === 'groups' && groups.length === 0) {
      fetchGroups()
    } else if (activeTab === 'campaigns' && campaigns.length === 0) {
      fetchCampaigns()
    }
  }, [activeTab])

  // Refetch campaigns when sort or search changes
  useEffect(() => {
    if (activeTab === 'campaigns') {
      fetchCampaigns()
    }
  }, [campaignSortBy, campaignSortOrder])

  const handleSync = async () => {
    setSyncing(true)
    setMessage(null)

    try {
      const result = await mitreApi.triggerSync()
      setMessage({
        type: 'success',
        text: result.message || 'Sync completed successfully',
      })
      // Refresh data after sync
      await fetchData()
    } catch (error: unknown) {
      const err = error as { response?: { data?: { detail?: string } } }
      setMessage({
        type: 'error',
        text: err.response?.data?.detail || 'Sync failed',
      })
    } finally {
      setSyncing(false)
    }
  }

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never'
    return new Date(dateStr).toLocaleString()
  }

  const formatDuration = (seconds: number | null) => {
    if (!seconds) return '-'
    if (seconds < 60) return `${seconds}s`
    return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  }

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
      pending: 'bg-yellow-100 text-yellow-800',
    }
    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${styles[status] || 'bg-gray-100 text-gray-800'}`}>
        {status}
      </span>
    )
  }

  if (!isInitialised || loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Link
                to="/admin/dashboard"
                className="text-gray-500 hover:text-gray-700 flex items-center"
              >
                <ChevronLeft className="h-5 w-5 mr-1" />
                Back
              </Link>
              <div className="flex items-center">
                <Database className="h-6 w-6 text-indigo-600 mr-2" />
                <h1 className="text-xl font-semibold text-gray-900">
                  MITRE ATT&CK Data
                </h1>
              </div>
            </div>
            <button
              onClick={handleSync}
              disabled={syncing}
              className="inline-flex items-center px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${syncing ? 'animate-spin' : ''}`} />
              {syncing ? 'Syncing...' : 'Sync Now'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
        {/* Message */}
        {message && (
          <div
            className={`mb-6 p-4 rounded-lg flex items-center ${
              message.type === 'success'
                ? 'bg-green-50 text-green-800'
                : 'bg-red-50 text-red-800'
            }`}
          >
            {message.type === 'success' ? (
              <Check className="h-5 w-5 mr-2" />
            ) : (
              <AlertCircle className="h-5 w-5 mr-2" />
            )}
            {message.text}
          </div>
        )}

        {/* Status Card */}
        <div className="bg-white rounded-lg shadow-sm border p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Sync Status</h2>
            {status?.is_synced ? (
              <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-medium">
                Data Synced
              </span>
            ) : (
              <span className="px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full text-sm font-medium">
                Not Synced
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center text-gray-500 mb-1">
                <Clock className="h-4 w-4 mr-1" />
                <span className="text-sm">Last Sync</span>
              </div>
              <p className="text-lg font-semibold text-gray-900">
                {formatDate(status?.last_sync_at || null)}
              </p>
            </div>
            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center text-gray-500 mb-1">
                <Database className="h-4 w-4 mr-1" />
                <span className="text-sm">MITRE Version</span>
              </div>
              <p className="text-lg font-semibold text-gray-900">
                {status?.mitre_version || 'N/A'}
              </p>
            </div>
            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center text-gray-500 mb-1">
                <Calendar className="h-4 w-4 mr-1" />
                <span className="text-sm">STIX Version</span>
              </div>
              <p className="text-lg font-semibold text-gray-900">
                {status?.stix_version || 'N/A'}
              </p>
            </div>
            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center text-gray-500 mb-1">
                <RefreshCw className="h-4 w-4 mr-1" />
                <span className="text-sm">Last Status</span>
              </div>
              <p className="text-lg font-semibold text-gray-900">
                {status?.last_sync_status || 'N/A'}
              </p>
            </div>
          </div>
        </div>

        {/* Statistics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow-sm border p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Threat Groups</p>
                <p className="text-2xl font-bold text-gray-900">
                  {status?.total_groups || 0}
                </p>
              </div>
              <Users className="h-8 w-8 text-indigo-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow-sm border p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Campaigns</p>
                <p className="text-2xl font-bold text-gray-900">
                  {status?.total_campaigns || 0}
                </p>
              </div>
              <Target className="h-8 w-8 text-orange-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow-sm border p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Software</p>
                <p className="text-2xl font-bold text-gray-900">
                  {status?.total_software || 0}
                </p>
              </div>
              <Package className="h-8 w-8 text-green-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow-sm border p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Relationships</p>
                <p className="text-2xl font-bold text-gray-900">
                  {status?.total_relationships || 0}
                </p>
              </div>
              <LinkIcon className="h-8 w-8 text-purple-500" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="border-b">
            <nav className="flex -mb-px">
              {(['overview', 'groups', 'campaigns', 'history'] as TabType[]).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-6 py-4 text-sm font-medium border-b-2 ${
                    activeTab === tab
                      ? 'border-indigo-600 text-indigo-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'overview' && (
              <div className="text-center py-12 text-gray-500">
                <Database className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  MITRE ATT&CK Threat Intelligence
                </h3>
                <p className="max-w-md mx-auto">
                  This page allows you to sync and browse MITRE ATT&CK threat intelligence data.
                  Click "Sync Now" to download the latest data from MITRE.
                </p>
              </div>
            )}

            {activeTab === 'groups' && (
              <div>
                <div className="mb-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search groups by name or alias..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && fetchGroups()}
                      className="pl-10 pr-4 py-2 w-full border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>
                </div>

                {groups.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    No threat groups found. Click "Sync Now" to download data.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Aliases</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Seen</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Link</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {groups.map((group) => (
                          <tr key={group.id} className="hover:bg-gray-50">
                            <td className="px-4 py-3 text-sm font-mono text-gray-900">
                              {group.external_id}
                            </td>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">
                              {group.name}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {group.aliases.slice(0, 3).join(', ')}
                              {group.aliases.length > 3 && ` +${group.aliases.length - 3} more`}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {group.last_seen ? new Date(group.last_seen).getFullYear() : '-'}
                            </td>
                            <td className="px-4 py-3">
                              <a
                                href={group.mitre_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-indigo-600 hover:text-indigo-800"
                              >
                                <ExternalLink className="h-4 w-4" />
                              </a>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'campaigns' && (
              <div>
                <div className="mb-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search campaigns by name or ID..."
                      value={campaignSearch}
                      onChange={(e) => setCampaignSearch(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && fetchCampaigns()}
                      className="pl-10 pr-4 py-2 w-full border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>
                </div>

                {campaigns.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    No campaigns found. {campaignSearch ? 'Try a different search term.' : 'Click "Sync Now" to download data.'}
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th
                            onClick={() => handleCampaignSort('external_id')}
                            className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase cursor-pointer hover:bg-gray-100"
                          >
                            ID <SortIcon field="external_id" />
                          </th>
                          <th
                            onClick={() => handleCampaignSort('name')}
                            className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase cursor-pointer hover:bg-gray-100"
                          >
                            Name <SortIcon field="name" />
                          </th>
                          <th
                            onClick={() => handleCampaignSort('first_seen')}
                            className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase cursor-pointer hover:bg-gray-100"
                          >
                            First Seen <SortIcon field="first_seen" />
                          </th>
                          <th
                            onClick={() => handleCampaignSort('last_seen')}
                            className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase cursor-pointer hover:bg-gray-100"
                          >
                            Last Seen <SortIcon field="last_seen" />
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Link</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {campaigns.map((campaign) => (
                          <tr key={campaign.id} className="hover:bg-gray-50">
                            <td className="px-4 py-3 text-sm font-mono text-gray-900">
                              {campaign.external_id}
                            </td>
                            <td className="px-4 py-3 text-sm font-medium text-gray-900">
                              {campaign.name}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {campaign.first_seen ? new Date(campaign.first_seen).getFullYear() : '-'}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {campaign.last_seen ? new Date(campaign.last_seen).getFullYear() : '-'}
                            </td>
                            <td className="px-4 py-3">
                              <a
                                href={campaign.mitre_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-indigo-600 hover:text-indigo-800"
                              >
                                <ExternalLink className="h-4 w-4" />
                              </a>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'history' && (
              <div>
                {syncHistory.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    No sync history yet. Click "Sync Now" to start.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Started</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Version</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trigger</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Duration</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Groups</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Campaigns</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {syncHistory.map((h) => (
                          <tr key={h.id} className="hover:bg-gray-50">
                            <td className="px-4 py-3 text-sm text-gray-900">
                              {formatDate(h.started_at)}
                            </td>
                            <td className="px-4 py-3">
                              {getStatusBadge(h.status)}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {h.mitre_version || '-'}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500 capitalize">
                              {h.trigger_type}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {formatDuration(h.duration_seconds)}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {h.stats?.groups_added ?? '-'}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-500">
                              {h.stats?.campaigns_added ?? '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
