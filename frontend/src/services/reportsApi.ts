/**
 * Reports API Service
 *
 * Provides access to report generation and download endpoints.
 * Note: Free tier reports are watermarked - this is handled by the backend.
 */

import axios from 'axios'

// Use environment variable for API base URL (production uses full URL, dev uses proxy)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/reports`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export type ReportType = 'coverage' | 'gaps' | 'detections' | 'executive' | 'full' | 'compliance'
export type ReportFormat = 'csv' | 'pdf' | 'json'

export interface ReportOptions {
  cloudAccountId: string
  includeGaps?: boolean
  includeDetections?: boolean
}

export interface ReportDownloadResult {
  blob: Blob
  filename: string
  contentType: string
}

export interface ReportMetadata {
  id: string
  report_type: ReportType
  format: ReportFormat
  cloud_account_id: string
  account_name: string
  generated_at: string
  file_size_bytes?: number
  is_watermarked: boolean
}

// Helper to get filename from Content-Disposition header
function getFilenameFromHeader(header: string | null, fallback: string): string {
  if (!header) return fallback
  const match = header.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
  if (match && match[1]) {
    return match[1].replace(/['"]/g, '')
  }
  return fallback
}

// API functions
export const reportsApi = {
  /**
   * Download coverage CSV report
   */
  downloadCoverageCsv: async (
    token: string,
    cloudAccountId: string
  ): Promise<ReportDownloadResult> => {
    const response = await api.get('/coverage/csv', {
      headers: { Authorization: `Bearer ${token}` },
      params: { cloud_account_id: cloudAccountId },
      responseType: 'blob',
    })

    return {
      blob: response.data,
      filename: getFilenameFromHeader(
        response.headers['content-disposition'],
        `coverage_report_${cloudAccountId}.csv`
      ),
      contentType: 'text/csv',
    }
  },

  /**
   * Download gaps CSV report
   */
  downloadGapsCsv: async (
    token: string,
    cloudAccountId: string
  ): Promise<ReportDownloadResult> => {
    const response = await api.get('/gaps/csv', {
      headers: { Authorization: `Bearer ${token}` },
      params: { cloud_account_id: cloudAccountId },
      responseType: 'blob',
    })

    return {
      blob: response.data,
      filename: getFilenameFromHeader(
        response.headers['content-disposition'],
        `gaps_report_${cloudAccountId}.csv`
      ),
      contentType: 'text/csv',
    }
  },

  /**
   * Download detections CSV report
   */
  downloadDetectionsCsv: async (
    token: string,
    cloudAccountId: string
  ): Promise<ReportDownloadResult> => {
    const response = await api.get('/detections/csv', {
      headers: { Authorization: `Bearer ${token}` },
      params: { cloud_account_id: cloudAccountId },
      responseType: 'blob',
    })

    return {
      blob: response.data,
      filename: getFilenameFromHeader(
        response.headers['content-disposition'],
        `detections_report_${cloudAccountId}.csv`
      ),
      contentType: 'text/csv',
    }
  },

  /**
   * Download executive summary PDF report
   * Note: Free tier reports will include a watermark
   */
  downloadExecutivePdf: async (
    token: string,
    cloudAccountId: string,
    options?: { includeGaps?: boolean; includeDetections?: boolean }
  ): Promise<ReportDownloadResult> => {
    const response = await api.get('/executive/pdf', {
      headers: { Authorization: `Bearer ${token}` },
      params: {
        cloud_account_id: cloudAccountId,
        include_gaps: options?.includeGaps ?? true,
        include_detections: options?.includeDetections ?? false,
      },
      responseType: 'blob',
    })

    return {
      blob: response.data,
      filename: getFilenameFromHeader(
        response.headers['content-disposition'],
        `executive_report_${cloudAccountId}.pdf`
      ),
      contentType: 'application/pdf',
    }
  },

  /**
   * Download full PDF report with all sections
   * Note: Free tier reports will include a watermark
   */
  downloadFullPdf: async (
    token: string,
    cloudAccountId: string
  ): Promise<ReportDownloadResult> => {
    const response = await api.get('/full/pdf', {
      headers: { Authorization: `Bearer ${token}` },
      params: { cloud_account_id: cloudAccountId },
      responseType: 'blob',
    })

    return {
      blob: response.data,
      filename: getFilenameFromHeader(
        response.headers['content-disposition'],
        `full_report_${cloudAccountId}.pdf`
      ),
      contentType: 'application/pdf',
    }
  },

  /**
   * Download compliance summary PDF report
   * Dedicated report showing NIST 800-53 and CIS Controls coverage
   */
  downloadCompliancePdf: async (
    token: string,
    cloudAccountId: string
  ): Promise<ReportDownloadResult> => {
    const response = await api.get('/compliance/pdf', {
      headers: { Authorization: `Bearer ${token}` },
      params: { cloud_account_id: cloudAccountId },
      responseType: 'blob',
    })

    return {
      blob: response.data,
      filename: getFilenameFromHeader(
        response.headers['content-disposition'],
        `compliance_report_${cloudAccountId}.pdf`
      ),
      contentType: 'application/pdf',
    }
  },
}

/**
 * Helper to trigger browser download of a report
 */
export function downloadReport(result: ReportDownloadResult): void {
  const url = window.URL.createObjectURL(result.blob)
  const link = document.createElement('a')
  link.href = url
  link.download = result.filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)
}

export default reportsApi
