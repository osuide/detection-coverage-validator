import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1/audit-logs',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface AuditLogActor {
  id: string | null
  email: string | null
  full_name: string | null
}

export interface AuditLogEntry {
  id: string
  action: string
  resource_type: string | null
  resource_id: string | null
  details: Record<string, unknown> | null
  ip_address: string | null
  success: boolean
  error_message: string | null
  created_at: string
  actor: AuditLogActor | null
}

export interface AuditLogListResponse {
  items: AuditLogEntry[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface AuditStats {
  total_events: number
  events_today: number
  events_this_week: number
  top_actions: { action: string; count: number }[]
  top_actors: { user_id: string; full_name: string; email: string; count: number }[]
}

export interface AuditAction {
  value: string
  label: string
  category: string
}

export interface ListAuditLogsParams {
  page?: number
  page_size?: number
  action?: string
  actor_id?: string
  resource_type?: string
  resource_id?: string
  start_date?: string
  end_date?: string
}

// API functions
export const auditApi = {
  // List audit logs
  getAuditLogs: async (token: string, params?: ListAuditLogsParams): Promise<AuditLogListResponse> => {
    const response = await api.get<AuditLogListResponse>('', {
      headers: { Authorization: `Bearer ${token}` },
      params,
    })
    return response.data
  },

  // Get audit stats
  getStats: async (token: string): Promise<AuditStats> => {
    const response = await api.get<AuditStats>('/stats', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Get action types
  getActionTypes: async (token: string): Promise<{ actions: AuditAction[] }> => {
    const response = await api.get<{ actions: AuditAction[] }>('/actions', {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },

  // Get single audit log
  getAuditLog: async (token: string, logId: string): Promise<AuditLogEntry> => {
    const response = await api.get<AuditLogEntry>(`/${logId}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.data
  },
}

export default auditApi
