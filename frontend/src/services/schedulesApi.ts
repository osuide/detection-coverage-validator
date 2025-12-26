/**
 * Schedules API client for automated scan scheduling.
 */

import api from './api'

export type ScheduleFrequency = 'hourly' | 'daily' | 'weekly' | 'monthly' | 'custom'

export interface Schedule {
  id: string
  cloud_account_id: string
  name: string
  description: string | null
  frequency: ScheduleFrequency
  cron_expression: string | null
  day_of_week: number | null // 0=Monday, 6=Sunday
  day_of_month: number | null // 1-31
  hour: number // 0-23
  minute: number // 0-59
  timezone: string
  regions: string[]
  detection_types: string[]
  is_active: boolean
  last_run_at: string | null
  next_run_at: string | null
  run_count: number
  last_scan_id: string | null
  created_at: string
  updated_at: string
}

export interface ScheduleCreate {
  cloud_account_id: string
  name: string
  description?: string
  frequency: ScheduleFrequency
  cron_expression?: string
  day_of_week?: number
  day_of_month?: number
  hour?: number
  minute?: number
  timezone?: string
  regions?: string[]
  detection_types?: string[]
}

export interface ScheduleUpdate {
  name?: string
  description?: string
  frequency?: ScheduleFrequency
  cron_expression?: string
  day_of_week?: number
  day_of_month?: number
  hour?: number
  minute?: number
  timezone?: string
  regions?: string[]
  detection_types?: string[]
  is_active?: boolean
}

export interface ScheduleListResponse {
  items: Schedule[]
  total: number
  page: number
  page_size: number
}

export interface JobStatus {
  job_id: string
  name: string
  next_run_time: string | null
  pending: boolean
}

export interface ScheduleStatusResponse {
  schedule: Schedule
  job_status: JobStatus | null
}

export const schedulesApi = {
  /**
   * List all schedules, optionally filtered by cloud account.
   */
  list: async (cloudAccountId?: string): Promise<Schedule[]> => {
    const params = cloudAccountId ? { cloud_account_id: cloudAccountId } : {}
    const response = await api.get<ScheduleListResponse>('/schedules', { params })
    return response.data.items
  },

  /**
   * Get a specific schedule by ID.
   */
  get: async (scheduleId: string): Promise<Schedule> => {
    const response = await api.get<Schedule>(`/schedules/${scheduleId}`)
    return response.data
  },

  /**
   * Get schedule status including job information.
   */
  getStatus: async (scheduleId: string): Promise<ScheduleStatusResponse> => {
    const response = await api.get<ScheduleStatusResponse>(`/schedules/${scheduleId}/status`)
    return response.data
  },

  /**
   * Create a new schedule.
   */
  create: async (data: ScheduleCreate): Promise<Schedule> => {
    const response = await api.post<Schedule>('/schedules', data)
    return response.data
  },

  /**
   * Update an existing schedule.
   */
  update: async (scheduleId: string, data: ScheduleUpdate): Promise<Schedule> => {
    const response = await api.put<Schedule>(`/schedules/${scheduleId}`, data)
    return response.data
  },

  /**
   * Delete a schedule.
   */
  delete: async (scheduleId: string): Promise<void> => {
    await api.delete(`/schedules/${scheduleId}`)
  },

  /**
   * Activate a paused schedule.
   */
  activate: async (scheduleId: string): Promise<Schedule> => {
    const response = await api.post<Schedule>(`/schedules/${scheduleId}/activate`)
    return response.data
  },

  /**
   * Deactivate (pause) a schedule.
   */
  deactivate: async (scheduleId: string): Promise<Schedule> => {
    const response = await api.post<Schedule>(`/schedules/${scheduleId}/deactivate`)
    return response.data
  },

  /**
   * Trigger an immediate run of a schedule.
   */
  runNow: async (scheduleId: string): Promise<Schedule> => {
    const response = await api.post<Schedule>(`/schedules/${scheduleId}/run-now`)
    return response.data
  },

  /**
   * Get schedule for a specific cloud account (convenience method).
   */
  getForAccount: async (cloudAccountId: string): Promise<Schedule | null> => {
    const schedules = await schedulesApi.list(cloudAccountId)
    return schedules.length > 0 ? schedules[0] : null
  },
}

export default schedulesApi
