import { useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ChevronLeft,
  Cloud,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Link2,
  XCircle,
  Check,
  Search,
} from 'lucide-react'
import {
  cloudOrganizationsApi,
  CloudOrganizationMember,
} from '../services/organizationsApi'

export default function OrganizationMembers() {
  const { orgId } = useParams<{ orgId: string }>()
  const queryClient = useQueryClient()
  const [selectedMembers, setSelectedMembers] = useState<Set<string>>(new Set())
  const [searchQuery, setSearchQuery] = useState('')

  // Fetch organisation details
  const { data: organization, isLoading: orgLoading } = useQuery({
    queryKey: ['cloud-organization', orgId],
    queryFn: () => cloudOrganizationsApi.get(orgId!),
    enabled: !!orgId,
  })

  // Fetch members
  const { data: members, isLoading: membersLoading } = useQuery({
    queryKey: ['cloud-organization-members', orgId],
    queryFn: () => cloudOrganizationsApi.getMembers(orgId!),
    enabled: !!orgId,
  })

  // Connect members mutation
  const connectMutation = useMutation({
    mutationFn: (memberIds: string[]) =>
      cloudOrganizationsApi.connectMembers(orgId!, { member_ids: memberIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['cloud-organization-members', orgId],
      })
      queryClient.invalidateQueries({
        queryKey: ['cloud-organization', orgId],
      })
      setSelectedMembers(new Set())
    },
  })

  // Filter members by search
  const filteredMembers = useMemo(() => {
    if (!searchQuery) return members || []
    const query = searchQuery.toLowerCase()
    return (members || []).filter(
      (m) =>
        m.member_name.toLowerCase().includes(query) ||
        m.member_account_id.toLowerCase().includes(query) ||
        m.hierarchy_path.toLowerCase().includes(query)
    )
  }, [members, searchQuery])

  const toggleMember = (memberId: string) => {
    const newSelected = new Set(selectedMembers)
    if (newSelected.has(memberId)) {
      newSelected.delete(memberId)
    } else {
      newSelected.add(memberId)
    }
    setSelectedMembers(newSelected)
  }

  const selectAll = () => {
    const discoveredMembers = (members || []).filter(
      (m) => m.status === 'discovered'
    )
    setSelectedMembers(new Set(discoveredMembers.map((m) => m.id)))
  }

  const selectNone = () => {
    setSelectedMembers(new Set())
  }

  const handleConnect = () => {
    if (selectedMembers.size > 0) {
      connectMutation.mutate(Array.from(selectedMembers))
    }
  }

  if (orgLoading || membersLoading) {
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
        <h2 className="text-lg font-medium text-gray-900">
          Organisation not found
        </h2>
      </div>
    )
  }

  const discoveredCount = (members || []).filter(
    (m) => m.status === 'discovered'
  ).length
  const connectedCount = (members || []).filter(
    (m) => m.status === 'connected'
  ).length

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <Link
          to={`/organizations/${orgId}`}
          className="text-gray-600 hover:text-gray-900 flex items-center mb-4"
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Back to {organization.name}
        </Link>

        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              Member Accounts
            </h1>
            <p className="text-gray-600">
              {connectedCount} connected, {discoveredCount} available to connect
            </p>
          </div>
          <div className="flex items-center space-x-2">
            {selectedMembers.size > 0 && (
              <button
                onClick={handleConnect}
                disabled={connectMutation.isPending}
                className="btn-primary flex items-center"
              >
                {connectMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Link2 className="h-4 w-4 mr-2" />
                )}
                Connect {selectedMembers.size} Account
                {selectedMembers.size > 1 ? 's' : ''}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Search and Actions */}
      <div className="card mb-6">
        <div className="flex items-center justify-between">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search accounts..."
              className="w-full pl-9 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div className="flex items-center space-x-2 ml-4">
            <button onClick={selectAll} className="text-sm text-blue-600 hover:underline">
              Select all discovered
            </button>
            <span className="text-gray-300">|</span>
            <button onClick={selectNone} className="text-sm text-gray-600 hover:underline">
              Clear selection
            </button>
          </div>
        </div>
      </div>

      {/* Members List */}
      <div className="card">
        {!members?.length ? (
          <div className="text-center py-8 text-gray-500">
            No accounts discovered
          </div>
        ) : (
          <div className="divide-y">
            {filteredMembers.map((member) => (
              <MemberRow
                key={member.id}
                member={member}
                isSelected={selectedMembers.has(member.id)}
                onToggle={() => toggleMember(member.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// Member Row Component
function MemberRow({
  member,
  isSelected,
  onToggle,
}: {
  member: CloudOrganizationMember
  isSelected: boolean
  onToggle: () => void
}) {
  const getStatusBadge = () => {
    switch (member.status) {
      case 'connected':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-green-100 text-green-800 flex items-center">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            Connected
          </span>
        )
      case 'connecting':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800 flex items-center">
            <Loader2 className="w-3 h-3 mr-1 animate-spin" />
            Connecting
          </span>
        )
      case 'discovered':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-800">
            Available
          </span>
        )
      case 'skipped':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-yellow-100 text-yellow-800 flex items-center">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Skipped
          </span>
        )
      case 'error':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-800 flex items-center">
            <XCircle className="w-3 h-3 mr-1" />
            Error
          </span>
        )
      case 'suspended':
        return (
          <span className="px-2 py-1 text-xs rounded-full bg-gray-100 text-gray-600">
            Suspended
          </span>
        )
      default:
        return null
    }
  }

  const canSelect = member.status === 'discovered'

  return (
    <div
      className={`flex items-center py-3 px-2 hover:bg-gray-50 ${
        isSelected ? 'bg-blue-50' : ''
      }`}
    >
      {/* Checkbox */}
      <div className="mr-3">
        {canSelect ? (
          <button
            onClick={onToggle}
            className={`w-5 h-5 rounded border flex items-center justify-center ${
              isSelected
                ? 'bg-blue-600 border-blue-600'
                : 'border-gray-300 hover:border-gray-400'
            }`}
          >
            {isSelected && <Check className="w-3 h-3 text-white" />}
          </button>
        ) : (
          <div className="w-5 h-5" />
        )}
      </div>

      {/* Account Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center space-x-2">
          <Cloud className="h-4 w-4 text-gray-400 flex-shrink-0" />
          <span className="font-medium text-gray-900 truncate">
            {member.member_name}
          </span>
          {getStatusBadge()}
        </div>
        <div className="flex items-center text-sm text-gray-500 mt-1">
          <span className="font-mono">{member.member_account_id}</span>
          <span className="mx-2">&middot;</span>
          <span className="truncate">{member.hierarchy_path}</span>
        </div>
      </div>

      {/* Actions */}
      <div>
        {member.status === 'connected' && member.cloud_account_id && (
          <Link
            to={`/accounts`}
            className="text-sm text-blue-600 hover:underline"
          >
            View account &rarr;
          </Link>
        )}
      </div>
    </div>
  )
}
