import axios from 'axios'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/teams`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export type UserRole = 'owner' | 'admin' | 'member' | 'viewer'
export type MembershipStatus = 'active' | 'pending' | 'suspended' | 'removed'

export interface Member {
  id: string
  user_id: string
  email: string
  full_name: string
  avatar_url: string | null
  role: UserRole
  status: MembershipStatus
  joined_at: string
}

export interface PendingInvite {
  id: string
  email: string
  role: UserRole
  invited_at: string
  expires_at: string
  invited_by_name: string
}

export interface InviteRequest {
  email: string
  role: UserRole
  message?: string
}

export interface InviteResponse {
  id: string
  email: string
  role: UserRole
  status: MembershipStatus
  invited_at: string
  expires_at: string
}

// API functions
export const teamsApi = {
  // Get all members
  getMembers: async (token: string): Promise<Member[]> => {
    const response = await api.get<Member[]>('/members', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Get pending invites
  getPendingInvites: async (token: string): Promise<PendingInvite[]> => {
    const response = await api.get<PendingInvite[]>('/invites', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Invite a new member
  inviteMember: async (token: string, data: InviteRequest): Promise<InviteResponse> => {
    const response = await api.post<InviteResponse>('/invites', data, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Cancel an invite
  cancelInvite: async (token: string, inviteId: string): Promise<void> => {
    await api.delete(`/invites/${inviteId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  },

  // Update member role
  updateMemberRole: async (token: string, memberId: string, role: UserRole): Promise<Member> => {
    const response = await api.patch<Member>(
      `/members/${memberId}/role`,
      { role },
      { headers: { Authorization: `Bearer ${token}` } }
    )
    return response.data
  },

  // Remove a member
  removeMember: async (token: string, memberId: string): Promise<void> => {
    await api.delete(`/members/${memberId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  },

  // Leave organization
  leaveOrganization: async (token: string): Promise<void> => {
    await api.post('/leave', {}, {
      headers: { Authorization: `Bearer ${token}` },
    })
  },

  // Accept an invite
  acceptInvite: async (token: string, inviteToken: string): Promise<Member> => {
    const response = await api.post<Member>(
      '/invites/accept',
      { invite_token: inviteToken },
      { headers: { Authorization: `Bearer ${token}` } }
    )
    return response.data
  },
}

export default teamsApi
