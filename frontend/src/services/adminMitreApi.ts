/**
 * Admin MITRE ATT&CK API service
 */

import { adminApi } from '../stores/adminAuthStore'

export interface MitreStatus {
  is_synced: boolean
  mitre_version: string | null
  stix_version: string | null
  last_sync_at: string | null
  last_sync_status: string | null
  total_groups: number
  total_campaigns: number
  total_software: number
  total_relationships: number
  next_scheduled_sync: string | null
  schedule_enabled: boolean
}

export interface MitreSyncResponse {
  sync_id: string
  status: string
  message: string
  estimated_duration_seconds: number
}

export interface MitreSyncHistory {
  id: string
  started_at: string
  completed_at: string | null
  status: string
  mitre_version: string | null
  stix_version: string | null
  trigger_type: string
  triggered_by_email: string | null
  stats: Record<string, number>
  error_message: string | null
  duration_seconds: number | null
}

export interface MitreSchedule {
  enabled: boolean
  cron_expression: string | null
  next_run_at: string | null
  timezone: string
}

export interface ThreatGroupSummary {
  id: string
  external_id: string
  name: string
  aliases: string[]
  first_seen: string | null
  last_seen: string | null
  techniques_count: number
  mitre_url: string
}

export interface CampaignSummary {
  id: string
  external_id: string
  name: string
  first_seen: string | null
  last_seen: string | null
  techniques_count: number
  mitre_url: string
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  skip: number
  limit: number
  has_more: boolean
}

export interface MitreStatistics {
  is_synced: boolean
  mitre_version: string | null
  stix_version: string | null
  last_sync_at: string | null
  total_groups: number
  total_campaigns: number
  total_software: number
  total_relationships: number
}

export const mitreApi = {
  // Status
  getStatus: () =>
    adminApi.get<MitreStatus>('/mitre/status').then(r => r.data),

  // Sync operations
  triggerSync: () =>
    adminApi.post<MitreSyncResponse>('/mitre/sync').then(r => r.data),

  getSyncHistory: (limit = 20) =>
    adminApi.get<MitreSyncHistory[]>('/mitre/sync/history', { params: { limit } }).then(r => r.data),

  // Schedule
  getSchedule: () =>
    adminApi.get<MitreSchedule>('/mitre/schedule').then(r => r.data),

  updateSchedule: (enabled: boolean, cronExpression?: string) =>
    adminApi.put<MitreSchedule>('/mitre/schedule', {
      enabled,
      cron_expression: cronExpression,
    }).then(r => r.data),

  // Browse data
  getGroups: (skip = 0, limit = 50, search?: string) =>
    adminApi.get<PaginatedResponse<ThreatGroupSummary>>('/mitre/groups', {
      params: { skip, limit, search },
    }).then(r => r.data),

  getCampaigns: (skip = 0, limit = 50) =>
    adminApi.get<PaginatedResponse<CampaignSummary>>('/mitre/campaigns', {
      params: { skip, limit },
    }).then(r => r.data),

  // Statistics
  getStatistics: () =>
    adminApi.get<MitreStatistics>('/mitre/statistics').then(r => r.data),
}
