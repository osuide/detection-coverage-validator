/**
 * MSW Request Handlers
 *
 * Mock API handlers for testing. These intercept HTTP requests
 * and return mock responses without hitting the real backend.
 */

import { http, HttpResponse } from 'msw'

// Mock data factories
export const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  full_name: 'Test User',
  avatar_url: null,
  timezone: 'Europe/London',
  email_verified: true,
  mfa_enabled: false,
  created_at: '2024-01-01T00:00:00Z',
  role: 'owner' as const,
  identity_provider: 'email',
}

export const mockOrganization = {
  id: 'org-123',
  name: 'Test Organization',
  slug: 'test-org',
  logo_url: null,
  plan: 'free',
  require_mfa: false,
  created_at: '2024-01-01T00:00:00Z',
}

export const mockCloudAccount = {
  id: 'account-123',
  name: 'Production AWS',
  provider: 'aws' as const,
  account_id: '123456789012',
  regions: ['eu-west-2'],
  region_config: {
    mode: 'selected' as const,
    regions: ['eu-west-2'],
  },
  is_active: true,
  last_scan_at: '2024-01-15T10:00:00Z',
  created_at: '2024-01-01T00:00:00Z',
}

export const mockDetection = {
  id: 'detection-123',
  cloud_account_id: 'account-123',
  name: 'GuardDuty Finding',
  detection_type: 'guardduty',
  status: 'active',
  region: 'eu-west-2',
  mapping_count: 3,
  discovered_at: '2024-01-15T10:00:00Z',
}

export const mockCoverageData = {
  id: 'coverage-123',
  cloud_account_id: 'account-123',
  total_techniques: 168,
  covered_techniques: 45,
  partial_techniques: 30,
  uncovered_techniques: 93,
  coverage_percent: 26.8,
  average_confidence: 72.5,
  tactic_coverage: [
    {
      tactic_id: 'TA0001',
      tactic_name: 'Initial Access',
      covered: 5,
      partial: 3,
      uncovered: 10,
      total: 18,
      percent: 27.8,
    },
  ],
  total_detections: 50,
  active_detections: 48,
  mapped_detections: 45,
  top_gaps: [],
  mitre_version: '14.1',
  created_at: '2024-01-15T10:00:00Z',
}

export const mockScan = {
  id: 'scan-123',
  cloud_account_id: 'account-123',
  status: 'completed' as const,
  progress_percent: 100,
  current_step: null,
  detections_found: 50,
  created_at: '2024-01-15T10:00:00Z',
}

// API base URL
const API_BASE = '/api/v1'

export const handlers = [
  // Auth endpoints
  http.post(`${API_BASE}/auth/login`, async ({ request }) => {
    const body = await request.json() as { email: string; password: string }
    if (body.email === 'test@example.com' && body.password === 'password123') {
      return HttpResponse.json({
        access_token: 'mock-access-token',
        user: mockUser,
        organization: mockOrganization,
      })
    }
    if (body.email === 'mfa@example.com') {
      return HttpResponse.json({
        requires_mfa: true,
        mfa_token: 'mock-mfa-token',
      })
    }
    return HttpResponse.json(
      { detail: 'Invalid credentials' },
      { status: 401 }
    )
  }),

  http.post(`${API_BASE}/auth/login/mfa`, async ({ request }) => {
    const body = await request.json() as { mfa_token: string; code: string }
    if (body.code === '123456') {
      return HttpResponse.json({
        access_token: 'mock-access-token',
        user: { ...mockUser, mfa_enabled: true },
        organization: mockOrganization,
      })
    }
    return HttpResponse.json(
      { detail: 'Invalid MFA code' },
      { status: 401 }
    )
  }),

  http.post(`${API_BASE}/auth/signup`, async ({ request }) => {
    const body = await request.json() as {
      email: string
      password: string
      full_name: string
      organization_name: string
    }
    return HttpResponse.json({
      access_token: 'mock-access-token',
      user: {
        ...mockUser,
        email: body.email,
        full_name: body.full_name,
      },
      organization: {
        ...mockOrganization,
        name: body.organization_name,
      },
    })
  }),

  http.post(`${API_BASE}/auth/refresh-session`, () => {
    return HttpResponse.json({
      access_token: 'mock-refreshed-token',
      csrf_token: 'mock-csrf-token',
    })
  }),

  http.post(`${API_BASE}/auth/logout-session`, () => {
    return HttpResponse.json({ message: 'Logged out' })
  }),

  http.get(`${API_BASE}/auth/me`, () => {
    return HttpResponse.json(mockUser)
  }),

  http.get(`${API_BASE}/auth/me/organizations`, () => {
    return HttpResponse.json([mockOrganization])
  }),

  // Accounts endpoints
  http.get(`${API_BASE}/accounts`, () => {
    return HttpResponse.json([mockCloudAccount])
  }),

  http.get(`${API_BASE}/accounts/:id`, ({ params }) => {
    if (params.id === 'account-123') {
      return HttpResponse.json(mockCloudAccount)
    }
    return HttpResponse.json(
      { detail: 'Account not found' },
      { status: 404 }
    )
  }),

  http.post(`${API_BASE}/accounts`, async ({ request }) => {
    const body = await request.json() as Partial<typeof mockCloudAccount>
    return HttpResponse.json({
      ...mockCloudAccount,
      ...body,
      id: 'new-account-123',
    })
  }),

  http.patch(`${API_BASE}/accounts/:id`, async ({ params, request }) => {
    const body = await request.json() as Partial<typeof mockCloudAccount>
    return HttpResponse.json({
      ...mockCloudAccount,
      id: params.id as string,
      ...body,
    })
  }),

  http.delete(`${API_BASE}/accounts/:id`, () => {
    return HttpResponse.json({ message: 'Deleted' })
  }),

  // Regions endpoints
  http.get(`${API_BASE}/accounts/regions/:provider`, ({ params }) => {
    const provider = params.provider as string
    const regions = provider === 'aws'
      ? ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-west-2']
      : ['us-central1', 'europe-west1', 'europe-west2']
    return HttpResponse.json({
      provider,
      regions,
      default_regions: [regions[0]],
    })
  }),

  // Scans endpoints
  http.get(`${API_BASE}/scans`, () => {
    return HttpResponse.json({ items: [mockScan] })
  }),

  http.post(`${API_BASE}/scans`, async ({ request }) => {
    const body = await request.json() as { cloud_account_id: string }
    return HttpResponse.json({
      ...mockScan,
      cloud_account_id: body.cloud_account_id,
      status: 'pending',
      progress_percent: 0,
    })
  }),

  http.get(`${API_BASE}/scans/:id`, ({ params }) => {
    return HttpResponse.json({
      ...mockScan,
      id: params.id as string,
    })
  }),

  // Detections endpoints
  http.get(`${API_BASE}/detections`, () => {
    return HttpResponse.json({
      items: [mockDetection],
      total: 1,
    })
  }),

  http.get(`${API_BASE}/detections/:id`, ({ params }) => {
    return HttpResponse.json({
      ...mockDetection,
      id: params.id as string,
      source_arn: 'arn:aws:guardduty:eu-west-2:123456789012:detector/abc123',
      query_pattern: null,
      event_pattern: null,
      log_groups: null,
      description: 'Test detection',
      health_score: 85,
      is_managed: true,
    })
  }),

  http.get(`${API_BASE}/detections/:id/mappings`, ({ params }) => {
    return HttpResponse.json({
      detection_id: params.id as string,
      detection_name: 'GuardDuty Finding',
      mappings: [
        {
          id: 'mapping-1',
          technique_id: 'T1078',
          technique_name: 'Valid Accounts',
          confidence: 85,
          mapping_source: 'pattern_match',
          rationale: 'Detection monitors for account compromise',
          matched_indicators: ['IAM', 'credential'],
          created_at: '2024-01-15T10:00:00Z',
        },
      ],
    })
  }),

  http.get(`${API_BASE}/detections/sources/counts`, () => {
    return HttpResponse.json({
      counts: [
        { detection_type: 'guardduty', count: 25 },
        { detection_type: 'securityhub', count: 15 },
        { detection_type: 'cloudwatch_alarm', count: 10 },
      ],
      total: 50,
    })
  }),

  // Coverage endpoints
  http.get(`${API_BASE}/coverage/:accountId`, () => {
    return HttpResponse.json(mockCoverageData)
  }),

  http.post(`${API_BASE}/coverage/:accountId/calculate`, () => {
    return HttpResponse.json(mockCoverageData)
  }),

  http.get(`${API_BASE}/coverage/:accountId/techniques`, () => {
    return HttpResponse.json({
      techniques: [
        {
          technique_id: 'T1078',
          technique_name: 'Valid Accounts',
          tactic_id: 'TA0001',
          tactic_name: 'Initial Access',
          detection_count: 3,
          max_confidence: 85,
          status: 'covered',
          detection_names: ['GuardDuty Finding'],
          has_template: true,
        },
      ],
    })
  }),

  // Billing endpoints
  http.get(`${API_BASE}/billing/scan-status`, () => {
    return HttpResponse.json({
      can_scan: true,
      scans_used: 1,
      scans_allowed: 5,
      unlimited: false,
      next_available_at: null,
      week_resets_at: '2024-01-22T00:00:00Z',
    })
  }),

  // Credentials endpoints
  http.get(`${API_BASE}/credentials/setup/:accountId`, () => {
    return HttpResponse.json({
      provider: 'aws',
      a13e_aws_account_id: '123456789012',
      external_id: 'ext-123',
      iam_policy: {},
      custom_role: null,
      required_permissions: [
        { service: 'guardduty', action: 'guardduty:ListDetectors', purpose: 'List GuardDuty detectors' },
      ],
      not_requested: ['s3:*'],
      cloudformation_template_url: 'https://example.com/template.yaml',
      terraform_module_url: 'https://example.com/module.tf',
      gcloud_commands: null,
      manual_steps: ['Step 1', 'Step 2'],
    })
  }),

  http.get(`${API_BASE}/credentials/:accountId`, () => {
    return HttpResponse.json({
      id: 'cred-123',
      cloud_account_id: 'account-123',
      credential_type: 'aws_iam_role',
      status: 'valid',
      status_message: null,
      last_validated_at: '2024-01-15T10:00:00Z',
      granted_permissions: ['guardduty:ListDetectors'],
      missing_permissions: [],
      aws_role_arn: 'arn:aws:iam::123456789012:role/A13ERole',
      aws_external_id: 'ext-123',
      gcp_project_id: null,
      gcp_service_account_email: null,
    })
  }),

  http.post(`${API_BASE}/credentials/aws`, async ({ request }) => {
    const body = await request.json() as { cloud_account_id: string; role_arn: string }
    return HttpResponse.json({
      id: 'cred-new',
      cloud_account_id: body.cloud_account_id,
      credential_type: 'aws_iam_role',
      status: 'pending',
      status_message: null,
      last_validated_at: null,
      granted_permissions: null,
      missing_permissions: null,
      aws_role_arn: body.role_arn,
      aws_external_id: 'ext-123',
      gcp_project_id: null,
      gcp_service_account_email: null,
    })
  }),

  http.post(`${API_BASE}/credentials/validate/:accountId`, () => {
    return HttpResponse.json({
      status: 'valid',
      message: 'All permissions granted',
      granted_permissions: ['guardduty:ListDetectors'],
      missing_permissions: [],
    })
  }),

  // Gaps endpoints
  http.get(`${API_BASE}/gaps/acknowledged`, () => {
    return HttpResponse.json({
      acknowledged_technique_ids: ['T1078'],
      count: 1,
    })
  }),

  http.post(`${API_BASE}/gaps/:techniqueId/acknowledge`, ({ params }) => {
    return HttpResponse.json({
      message: 'Gap acknowledged',
      gap_id: 'gap-123',
      technique_id: params.techniqueId as string,
      status: 'acknowledged',
    })
  }),
]
