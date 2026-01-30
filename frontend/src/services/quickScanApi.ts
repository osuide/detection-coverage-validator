import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

/** Summary statistics from the quick scan. */
export interface QuickScanSummary {
  total_techniques: number
  covered_techniques: number
  coverage_percentage: number
  detections_found: number
  resources_parsed: number
  truncated: boolean
}

/** A single detected security control. */
export interface QuickScanDetection {
  name: string
  source_arn: string
  detection_type: string
}

/** A coverage gap — an uncovered MITRE ATT&CK technique. */
export interface QuickScanGap {
  technique_id: string
  technique_name: string
  tactic_name: string
  priority: string
}

/** Full response from the quick scan endpoint. */
export interface QuickScanResponse {
  summary: QuickScanSummary
  tactic_coverage: Record<string, { total: number; covered: number; percentage: number }>
  top_gaps: QuickScanGap[]
  detections: QuickScanDetection[]
  error?: string | null
}

/**
 * Public quick scan API — no authentication required.
 *
 * Uses a standalone axios instance (no auth interceptor) because
 * this endpoint is public and must work for unauthenticated users.
 */
export const quickScanApi = {
  analyse: (content: string) =>
    axios
      .post<QuickScanResponse>(`${API_BASE_URL}/api/v1/quick-scan/analyse`, { content })
      .then((r) => r.data),
}
