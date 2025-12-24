import { useState, useEffect, FormEvent } from 'react'
import {
  Users,
  UserPlus,
  Mail,
  Crown,
  Shield,
  User,
  Eye,
  MoreVertical,
  X,
  Clock,
  Trash2,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '../contexts/AuthContext'
import { teamsApi, Member, PendingInvite, UserRole } from '../services/teamsApi'

const roleConfig: Record<UserRole, { label: string; icon: typeof Crown; color: string; description: string }> = {
  owner: {
    label: 'Owner',
    icon: Crown,
    color: 'text-yellow-400',
    description: 'Full access. Can delete organization.',
  },
  admin: {
    label: 'Admin',
    icon: Shield,
    color: 'text-blue-400',
    description: 'Can manage team members and settings.',
  },
  member: {
    label: 'Member',
    icon: User,
    color: 'text-gray-400',
    description: 'Can view and edit most resources.',
  },
  viewer: {
    label: 'Viewer',
    icon: Eye,
    color: 'text-gray-500',
    description: 'Read-only access to resources.',
  },
}

export default function TeamManagement() {
  const { accessToken, user } = useAuth()
  const [members, setMembers] = useState<Member[]>([])
  const [invites, setInvites] = useState<PendingInvite[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Invite modal state
  const [showInviteModal, setShowInviteModal] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<UserRole>('member')
  const [inviteMessage, setInviteMessage] = useState('')
  const [isInviting, setIsInviting] = useState(false)

  // Menu state
  const [openMenuId, setOpenMenuId] = useState<string | null>(null)

  // Current user's role in the organization
  const currentUserMember = members.find(m => m.user_id === user?.id)
  const currentUserRole = currentUserMember?.role || 'viewer'
  const canManageTeam = ['owner', 'admin'].includes(currentUserRole)
  const isOwner = currentUserRole === 'owner'

  useEffect(() => {
    loadTeamData()
  }, [accessToken])

  const loadTeamData = async () => {
    if (!accessToken) return

    setIsLoading(true)
    setError(null)

    try {
      const [membersData, invitesData] = await Promise.all([
        teamsApi.getMembers(accessToken),
        canManageTeam ? teamsApi.getPendingInvites(accessToken).catch(() => []) : Promise.resolve([]),
      ])
      setMembers(membersData)
      setInvites(invitesData)
    } catch (err) {
      console.error('Failed to load team data:', err)
      setError('Failed to load team members')
    } finally {
      setIsLoading(false)
    }
  }

  const handleInvite = async (e: FormEvent) => {
    e.preventDefault()
    if (!accessToken) return

    setIsInviting(true)
    setError(null)

    try {
      await teamsApi.inviteMember(accessToken, {
        email: inviteEmail,
        role: inviteRole,
        message: inviteMessage || undefined,
      })
      setShowInviteModal(false)
      setInviteEmail('')
      setInviteRole('member')
      setInviteMessage('')
      loadTeamData()
    } catch (err: unknown) {
      const errorMessage = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        'Failed to send invite'
      setError(errorMessage)
    } finally {
      setIsInviting(false)
    }
  }

  const handleCancelInvite = async (inviteId: string) => {
    if (!accessToken) return

    try {
      await teamsApi.cancelInvite(accessToken, inviteId)
      loadTeamData()
    } catch (err) {
      console.error('Failed to cancel invite:', err)
    }
    setOpenMenuId(null)
  }

  const handleUpdateRole = async (memberId: string, newRole: UserRole) => {
    if (!accessToken) return

    try {
      await teamsApi.updateMemberRole(accessToken, memberId, newRole)
      loadTeamData()
    } catch (err: unknown) {
      const errorMessage = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        'Failed to update role'
      setError(errorMessage)
    }
    setOpenMenuId(null)
  }

  const handleRemoveMember = async (memberId: string) => {
    if (!accessToken) return

    if (!confirm('Are you sure you want to remove this member?')) return

    try {
      await teamsApi.removeMember(accessToken, memberId)
      loadTeamData()
    } catch (err: unknown) {
      const errorMessage = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        'Failed to remove member'
      setError(errorMessage)
    }
    setOpenMenuId(null)
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-cyan-500 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Team Management</h1>
          <p className="mt-1 text-sm text-gray-400">
            Manage your organization's team members and permissions
          </p>
        </div>
        {canManageTeam && (
          <button
            onClick={() => setShowInviteModal(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg shadow-sm text-white bg-cyan-600 hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500"
          >
            <UserPlus className="h-4 w-4 mr-2" />
            Invite Member
          </button>
        )}
      </div>

      {/* Error message */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-400 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Members list */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700">
          <div className="flex items-center">
            <Users className="h-5 w-5 text-gray-400 mr-2" />
            <h2 className="text-lg font-medium text-white">Team Members</h2>
            <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-gray-700/30 text-gray-400 rounded-full">
              {members.length}
            </span>
          </div>
        </div>

        <div className="divide-y divide-gray-700">
          {members.map((member) => {
            const RoleIcon = roleConfig[member.role].icon
            const isCurrentUser = member.user_id === user?.id
            const canModify = canManageTeam && !isCurrentUser &&
              (isOwner || (currentUserRole === 'admin' && !['owner', 'admin'].includes(member.role)))

            return (
              <div key={member.id} className="px-6 py-4 flex items-center justify-between hover:bg-gray-700">
                <div className="flex items-center">
                  <div className="h-10 w-10 rounded-full bg-gray-700/30 flex items-center justify-center">
                    {member.avatar_url ? (
                      <img
                        src={member.avatar_url}
                        alt={member.full_name}
                        className="h-10 w-10 rounded-full"
                      />
                    ) : (
                      <User className="h-5 w-5 text-gray-400" />
                    )}
                  </div>
                  <div className="ml-4">
                    <div className="flex items-center">
                      <span className="text-sm font-medium text-white">
                        {member.full_name}
                      </span>
                      {isCurrentUser && (
                        <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-cyan-900/30 text-cyan-400 rounded-full">
                          You
                        </span>
                      )}
                    </div>
                    <span className="text-sm text-gray-400">{member.email}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="flex items-center">
                    <RoleIcon className={clsx('h-4 w-4 mr-1', roleConfig[member.role].color)} />
                    <span className="text-sm text-gray-400">{roleConfig[member.role].label}</span>
                  </div>

                  <span className="text-xs text-gray-400">
                    Joined {formatDate(member.joined_at)}
                  </span>

                  {canModify && (
                    <div className="relative">
                      <button
                        onClick={() => setOpenMenuId(openMenuId === member.id ? null : member.id)}
                        className="p-1 rounded-md hover:bg-gray-700"
                      >
                        <MoreVertical className="h-4 w-4 text-gray-400" />
                      </button>

                      {openMenuId === member.id && (
                        <div className="absolute right-0 mt-1 w-48 bg-white rounded-lg shadow-lg border border-gray-700 py-1 z-10">
                          <div className="px-3 py-2 text-xs font-medium text-gray-400 uppercase tracking-wide">
                            Change Role
                          </div>
                          {(['admin', 'member', 'viewer'] as UserRole[]).map((role) => (
                            <button
                              key={role}
                              onClick={() => handleUpdateRole(member.id, role)}
                              disabled={
                                role === member.role ||
                                (role === 'admin' && !isOwner)
                              }
                              className={clsx(
                                'w-full px-3 py-2 text-left text-sm flex items-center',
                                role === member.role
                                  ? 'bg-gray-700/30 text-gray-400 cursor-not-allowed'
                                  : (role === 'admin' && !isOwner)
                                    ? 'text-gray-300 cursor-not-allowed'
                                    : 'hover:bg-gray-700 text-white'
                              )}
                            >
                              {roleConfig[role].label}
                              {role === member.role && (
                                <span className="ml-auto text-xs text-gray-400">Current</span>
                              )}
                            </button>
                          ))}
                          <div className="border-t border-gray-700 mt-1 pt-1">
                            <button
                              onClick={() => handleRemoveMember(member.id)}
                              className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-red-900/30 flex items-center"
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              Remove from team
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Pending Invites */}
      {canManageTeam && invites.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700">
            <div className="flex items-center">
              <Mail className="h-5 w-5 text-gray-400 mr-2" />
              <h2 className="text-lg font-medium text-white">Pending Invites</h2>
              <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-yellow-900/30 text-yellow-400 rounded-full">
                {invites.length}
              </span>
            </div>
          </div>

          <div className="divide-y divide-gray-700">
            {invites.map((invite) => {
              const RoleIcon = roleConfig[invite.role].icon

              return (
                <div key={invite.id} className="px-6 py-4 flex items-center justify-between hover:bg-gray-700">
                  <div className="flex items-center">
                    <div className="h-10 w-10 rounded-full bg-gray-700/30 flex items-center justify-center">
                      <Mail className="h-5 w-5 text-gray-400" />
                    </div>
                    <div className="ml-4">
                      <span className="text-sm font-medium text-white">{invite.email}</span>
                      <div className="flex items-center text-xs text-gray-400">
                        <span>Invited by {invite.invited_by_name}</span>
                        <span className="mx-1">-</span>
                        <Clock className="h-3 w-3 mr-1" />
                        <span>Expires {formatDate(invite.expires_at)}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className="flex items-center">
                      <RoleIcon className={clsx('h-4 w-4 mr-1', roleConfig[invite.role].color)} />
                      <span className="text-sm text-gray-400">{roleConfig[invite.role].label}</span>
                    </div>

                    <button
                      onClick={() => handleCancelInvite(invite.id)}
                      className="text-sm text-red-400 hover:text-red-300"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Role Reference */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700">
          <h2 className="text-lg font-medium text-white">Role Permissions</h2>
        </div>
        <div className="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {(Object.entries(roleConfig) as [UserRole, typeof roleConfig[UserRole]][]).map(([role, config]) => {
            const Icon = config.icon
            return (
              <div key={role} className="p-4 bg-gray-700/30 rounded-lg">
                <div className="flex items-center mb-2">
                  <Icon className={clsx('h-5 w-5 mr-2', config.color)} />
                  <span className="font-medium text-white">{config.label}</span>
                </div>
                <p className="text-sm text-gray-400">{config.description}</p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl max-w-md w-full mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h2 className="text-lg font-medium text-white">Invite Team Member</h2>
              <button
                onClick={() => setShowInviteModal(false)}
                className="text-gray-400 hover:text-gray-400"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleInvite} className="p-6 space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                  Email address
                </label>
                <input
                  type="email"
                  id="email"
                  required
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-cyan-500 focus:border-cyan-500 sm:text-sm"
                  placeholder="colleague@company.com"
                />
              </div>

              <div>
                <label htmlFor="role" className="block text-sm font-medium text-gray-700">
                  Role
                </label>
                <select
                  id="role"
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as UserRole)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-cyan-500 focus:border-cyan-500 sm:text-sm"
                >
                  <option value="viewer">Viewer - Read-only access</option>
                  <option value="member">Member - Can view and edit</option>
                  {isOwner && <option value="admin">Admin - Can manage team</option>}
                </select>
              </div>

              <div>
                <label htmlFor="message" className="block text-sm font-medium text-gray-700">
                  Personal message (optional)
                </label>
                <textarea
                  id="message"
                  rows={3}
                  value={inviteMessage}
                  onChange={(e) => setInviteMessage(e.target.value)}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-cyan-500 focus:border-cyan-500 sm:text-sm"
                  placeholder="Add a personal note to your invitation..."
                />
              </div>

              {error && (
                <div className="bg-red-900/30 border border-red-700 text-red-400 px-4 py-2 rounded-lg text-sm">
                  {error}
                </div>
              )}

              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-400 bg-white border border-gray-700 rounded-lg hover:bg-gray-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isInviting}
                  className="px-4 py-2 text-sm font-medium text-white bg-cyan-600 border border-transparent rounded-lg hover:bg-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isInviting ? 'Sending...' : 'Send Invite'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
