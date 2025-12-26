/**
 * ScheduleModal - Configure recurring scan schedules for cloud accounts.
 *
 * Design: "Precision Engineering" - clean, information-dense, with subtle
 * glows and transitions that suggest reliability and technical competence.
 */

import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  X,
  Calendar,
  Clock,
  Play,
  Pause,
  Trash2,
  Zap,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react'
import { schedulesApi, ScheduleFrequency, ScheduleCreate } from '../services/schedulesApi'

interface ScheduleModalProps {
  cloudAccountId: string
  accountName: string
  onClose: () => void
}

const DAYS_OF_WEEK = [
  { value: 0, label: 'Monday' },
  { value: 1, label: 'Tuesday' },
  { value: 2, label: 'Wednesday' },
  { value: 3, label: 'Thursday' },
  { value: 4, label: 'Friday' },
  { value: 5, label: 'Saturday' },
  { value: 6, label: 'Sunday' },
]

const FREQUENCIES: { value: ScheduleFrequency; label: string; description: string }[] = [
  { value: 'daily', label: 'Daily', description: 'Run once every day' },
  { value: 'weekly', label: 'Weekly', description: 'Run once per week' },
  { value: 'monthly', label: 'Monthly', description: 'Run once per month' },
]

export default function ScheduleModal({ cloudAccountId, accountName, onClose }: ScheduleModalProps) {
  const queryClient = useQueryClient()

  // Form state
  const [frequency, setFrequency] = useState<ScheduleFrequency>('daily')
  const [hour, setHour] = useState(9) // 9 AM default
  const [minute, setMinute] = useState(0)
  const [dayOfWeek, setDayOfWeek] = useState(0) // Monday
  const [dayOfMonth, setDayOfMonth] = useState(1)
  const [hasChanges, setHasChanges] = useState(false)

  // Fetch existing schedule for this account
  const { data: existingSchedule, isLoading } = useQuery({
    queryKey: ['schedule', cloudAccountId],
    queryFn: () => schedulesApi.getForAccount(cloudAccountId),
  })

  // Populate form with existing schedule
  useEffect(() => {
    if (existingSchedule) {
      setFrequency(existingSchedule.frequency)
      setHour(existingSchedule.hour)
      setMinute(existingSchedule.minute)
      if (existingSchedule.day_of_week !== null) {
        setDayOfWeek(existingSchedule.day_of_week)
      }
      if (existingSchedule.day_of_month !== null) {
        setDayOfMonth(existingSchedule.day_of_month)
      }
    }
  }, [existingSchedule])

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: ScheduleCreate) => schedulesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedule', cloudAccountId] })
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      setHasChanges(false)
    },
  })

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof schedulesApi.update>[1] }) =>
      schedulesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedule', cloudAccountId] })
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      setHasChanges(false)
    },
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => schedulesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedule', cloudAccountId] })
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      onClose()
    },
  })

  // Activate mutation
  const activateMutation = useMutation({
    mutationFn: (id: string) => schedulesApi.activate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedule', cloudAccountId] })
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
    },
  })

  // Deactivate mutation
  const deactivateMutation = useMutation({
    mutationFn: (id: string) => schedulesApi.deactivate(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedule', cloudAccountId] })
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
    },
  })

  // Run now mutation
  const runNowMutation = useMutation({
    mutationFn: (id: string) => schedulesApi.runNow(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedule', cloudAccountId] })
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const handleSave = () => {
    const scheduleData = {
      cloud_account_id: cloudAccountId,
      name: `${accountName} - ${frequency.charAt(0).toUpperCase() + frequency.slice(1)} Scan`,
      frequency,
      hour,
      minute,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      ...(frequency === 'weekly' && { day_of_week: dayOfWeek }),
      ...(frequency === 'monthly' && { day_of_month: dayOfMonth }),
    }

    if (existingSchedule) {
      updateMutation.mutate({ id: existingSchedule.id, data: scheduleData })
    } else {
      createMutation.mutate(scheduleData)
    }
  }

  const handleToggleActive = () => {
    if (!existingSchedule) return
    if (existingSchedule.is_active) {
      deactivateMutation.mutate(existingSchedule.id)
    } else {
      activateMutation.mutate(existingSchedule.id)
    }
  }

  const handleDelete = () => {
    if (!existingSchedule) return
    if (confirm('Are you sure you want to delete this schedule?')) {
      deleteMutation.mutate(existingSchedule.id)
    }
  }

  const handleRunNow = () => {
    if (!existingSchedule) return
    runNowMutation.mutate(existingSchedule.id)
  }

  const formatNextRun = (dateString: string | null) => {
    if (!dateString) return 'Not scheduled'
    const date = new Date(dateString)
    return date.toLocaleString(undefined, {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const formatLastRun = (dateString: string | null) => {
    if (!dateString) return 'Never'
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    const diffDays = Math.floor(diffHours / 24)

    if (diffDays > 0) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`
    if (diffHours > 0) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`
    return 'Just now'
  }

  const isPending = createMutation.isPending || updateMutation.isPending ||
    deleteMutation.isPending || activateMutation.isPending ||
    deactivateMutation.isPending || runNowMutation.isPending

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div
        className="bg-gray-800 rounded-xl border border-gray-700 shadow-2xl w-full max-w-lg overflow-hidden"
        style={{
          boxShadow: existingSchedule?.is_active
            ? '0 0 40px rgba(34, 211, 238, 0.1), 0 25px 50px -12px rgba(0, 0, 0, 0.5)'
            : '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
        }}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${existingSchedule?.is_active ? 'bg-cyan-500/20' : 'bg-gray-700'}`}>
              <Calendar className={`h-5 w-5 ${existingSchedule?.is_active ? 'text-cyan-400' : 'text-gray-400'}`} />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Scan Schedule</h2>
              <p className="text-sm text-gray-400">{accountName}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 text-gray-400 animate-spin" />
            </div>
          ) : (
            <>
              {/* Existing Schedule Status */}
              {existingSchedule && (
                <div className={`rounded-lg p-4 ${existingSchedule.is_active ? 'bg-cyan-500/10 border border-cyan-500/30' : 'bg-gray-700/50 border border-gray-600'}`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {existingSchedule.is_active ? (
                        <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                      ) : (
                        <Pause className="h-4 w-4 text-gray-400" />
                      )}
                      <span className={`text-sm font-medium ${existingSchedule.is_active ? 'text-cyan-400' : 'text-gray-400'}`}>
                        {existingSchedule.is_active ? 'Active' : 'Paused'}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500">
                      {existingSchedule.run_count} scan{existingSchedule.run_count !== 1 ? 's' : ''} completed
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">Next Scan</p>
                      <p className="text-white font-medium">{formatNextRun(existingSchedule.next_run_at)}</p>
                    </div>
                    <div>
                      <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">Last Run</p>
                      <p className="text-gray-300">{formatLastRun(existingSchedule.last_run_at)}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Frequency Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-3">Frequency</label>
                <div className="grid grid-cols-3 gap-2">
                  {FREQUENCIES.map((freq) => (
                    <button
                      key={freq.value}
                      onClick={() => {
                        setFrequency(freq.value)
                        setHasChanges(true)
                      }}
                      className={`p-3 rounded-lg border text-center transition-all ${
                        frequency === freq.value
                          ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-400'
                          : 'bg-gray-700/50 border-gray-600 text-gray-400 hover:border-gray-500'
                      }`}
                    >
                      <span className="block font-medium">{freq.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Day Selection (for weekly/monthly) */}
              {frequency === 'weekly' && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-3">Day of Week</label>
                  <select
                    value={dayOfWeek}
                    onChange={(e) => {
                      setDayOfWeek(Number(e.target.value))
                      setHasChanges(true)
                    }}
                    className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  >
                    {DAYS_OF_WEEK.map((day) => (
                      <option key={day.value} value={day.value}>
                        {day.label}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {frequency === 'monthly' && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-3">Day of Month</label>
                  <select
                    value={dayOfMonth}
                    onChange={(e) => {
                      setDayOfMonth(Number(e.target.value))
                      setHasChanges(true)
                    }}
                    className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  >
                    {Array.from({ length: 28 }, (_, i) => i + 1).map((day) => (
                      <option key={day} value={day}>
                        {day}{day === 1 ? 'st' : day === 2 ? 'nd' : day === 3 ? 'rd' : 'th'}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Time Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-3">
                  <Clock className="h-4 w-4 inline mr-2" />
                  Time (your local timezone)
                </label>
                <div className="flex gap-3">
                  <select
                    value={hour}
                    onChange={(e) => {
                      setHour(Number(e.target.value))
                      setHasChanges(true)
                    }}
                    className="flex-1 px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  >
                    {Array.from({ length: 24 }, (_, i) => i).map((h) => (
                      <option key={h} value={h}>
                        {h.toString().padStart(2, '0')}
                      </option>
                    ))}
                  </select>
                  <span className="flex items-center text-gray-400 text-xl">:</span>
                  <select
                    value={minute}
                    onChange={(e) => {
                      setMinute(Number(e.target.value))
                      setHasChanges(true)
                    }}
                    className="flex-1 px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  >
                    {[0, 15, 30, 45].map((m) => (
                      <option key={m} value={m}>
                        {m.toString().padStart(2, '0')}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-700 bg-gray-800/50">
          {existingSchedule ? (
            <div className="flex items-center justify-between">
              <div className="flex gap-2">
                <button
                  onClick={handleToggleActive}
                  disabled={isPending}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
                    existingSchedule.is_active
                      ? 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      : 'bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30'
                  }`}
                >
                  {existingSchedule.is_active ? (
                    <>
                      <Pause className="h-4 w-4" />
                      Pause
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4" />
                      Resume
                    </>
                  )}
                </button>
                <button
                  onClick={handleRunNow}
                  disabled={isPending || !existingSchedule.is_active}
                  className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg text-sm font-medium hover:bg-gray-600 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Zap className="h-4 w-4" />
                  Run Now
                </button>
                <button
                  onClick={handleDelete}
                  disabled={isPending}
                  className="px-4 py-2 text-red-400 hover:bg-red-500/20 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
              <button
                onClick={handleSave}
                disabled={isPending || !hasChanges}
                className="px-6 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          ) : (
            <div className="flex justify-end gap-3">
              <button
                onClick={onClose}
                className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg text-sm font-medium hover:bg-gray-600 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={isPending}
                className="px-6 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {createMutation.isPending ? 'Creating...' : 'Create Schedule'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

/**
 * ScheduleIndicator - Shows schedule status on account cards.
 * Displays next scan time with subtle glow when active.
 */
export function ScheduleIndicator({ cloudAccountId }: { cloudAccountId: string }) {
  const { data: schedule, isLoading } = useQuery({
    queryKey: ['schedule', cloudAccountId],
    queryFn: () => schedulesApi.getForAccount(cloudAccountId),
    staleTime: 30000, // Cache for 30 seconds
  })

  if (isLoading || !schedule) return null

  const formatNextRun = (dateString: string | null) => {
    if (!dateString) return null
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = date.getTime() - now.getTime()
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    const diffDays = Math.floor(diffHours / 24)

    if (diffDays > 1) return `in ${diffDays}d`
    if (diffHours > 1) return `in ${diffHours}h`
    return 'soon'
  }

  const nextRunText = formatNextRun(schedule.next_run_at)

  return (
    <div
      className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-xs ${
        schedule.is_active
          ? 'bg-cyan-500/20 text-cyan-400'
          : 'bg-gray-700/50 text-gray-500'
      }`}
      style={schedule.is_active ? {
        boxShadow: '0 0 10px rgba(34, 211, 238, 0.2)',
      } : undefined}
    >
      <Calendar className="h-3 w-3" />
      {schedule.is_active && nextRunText ? (
        <span>Next {nextRunText}</span>
      ) : (
        <span>Paused</span>
      )}
    </div>
  )
}
