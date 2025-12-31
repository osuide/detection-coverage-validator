/**
 * API Service Tests
 *
 * Tests for the API service functions including:
 * - Accounts API (CRUD operations)
 * - Scans API
 * - Detections API
 * - Coverage API
 * - Credentials API
 * - Gaps API
 */

import { describe, it, expect, beforeEach } from 'vitest'
import {
  accountsApi,
  scansApi,
  detectionsApi,
  coverageApi,
  credentialsApi,
  gapsApi,
  regionsApi,
  scanStatusApi,
} from './api'
import { useAuthStore } from '../stores/authStore'

// Set up mock auth token before tests
beforeEach(() => {
  useAuthStore.setState({
    accessToken: 'mock-test-token',
    csrfToken: 'mock-csrf',
    user: {
      id: 'user-123',
      email: 'test@example.com',
      full_name: 'Test User',
      mfa_enabled: false,
    },
    organization: {
      id: 'org-123',
      name: 'Test Org',
      slug: 'test-org',
      plan: 'free',
    },
    isAuthenticated: true,
    isLoading: false,
    isInitialised: true,
  })
})

describe('accountsApi', () => {
  describe('list', () => {
    it('should fetch list of cloud accounts', async () => {
      const accounts = await accountsApi.list()

      expect(accounts).toBeInstanceOf(Array)
      expect(accounts.length).toBeGreaterThan(0)
      expect(accounts[0]).toHaveProperty('id')
      expect(accounts[0]).toHaveProperty('name')
      expect(accounts[0]).toHaveProperty('provider')
    })
  })

  describe('get', () => {
    it('should fetch a specific account by ID', async () => {
      const account = await accountsApi.get('account-123')

      expect(account.id).toBe('account-123')
      expect(account.provider).toBe('aws')
      expect(account.name).toBe('Production AWS')
    })

    it('should throw error for non-existent account', async () => {
      await expect(accountsApi.get('non-existent')).rejects.toThrow()
    })
  })

  describe('create', () => {
    it('should create a new account', async () => {
      const newAccount = await accountsApi.create({
        name: 'New Account',
        provider: 'aws',
        account_id: '987654321098',
        regions: ['us-east-1'],
      })

      expect(newAccount).toHaveProperty('id')
      expect(newAccount.name).toBe('New Account')
    })
  })

  describe('update', () => {
    it('should update an existing account', async () => {
      const updated = await accountsApi.update('account-123', {
        name: 'Updated Name',
      })

      expect(updated.id).toBe('account-123')
      expect(updated.name).toBe('Updated Name')
    })
  })

  describe('delete', () => {
    it('should delete an account', async () => {
      await expect(accountsApi.delete('account-123')).resolves.not.toThrow()
    })
  })
})

describe('regionsApi', () => {
  describe('getAvailable', () => {
    it('should fetch available AWS regions', async () => {
      const result = await regionsApi.getAvailable('aws')

      expect(result.provider).toBe('aws')
      expect(result.regions).toBeInstanceOf(Array)
      expect(result.regions).toContain('eu-west-2')
      expect(result.default_regions).toBeInstanceOf(Array)
    })

    it('should fetch available GCP regions', async () => {
      const result = await regionsApi.getAvailable('gcp')

      expect(result.provider).toBe('gcp')
      expect(result.regions).toBeInstanceOf(Array)
    })
  })
})

describe('scansApi', () => {
  describe('list', () => {
    it('should fetch list of scans', async () => {
      const scans = await scansApi.list()

      expect(scans).toBeInstanceOf(Array)
    })

    it('should filter by account ID when provided', async () => {
      const scans = await scansApi.list('account-123')

      expect(scans).toBeInstanceOf(Array)
    })
  })

  describe('create', () => {
    it('should start a new scan', async () => {
      const scan = await scansApi.create({
        cloud_account_id: 'account-123',
      })

      expect(scan).toHaveProperty('id')
      expect(scan.cloud_account_id).toBe('account-123')
      expect(scan.status).toBe('pending')
    })
  })

  describe('get', () => {
    it('should fetch a specific scan', async () => {
      const scan = await scansApi.get('scan-123')

      expect(scan.id).toBe('scan-123')
      expect(scan).toHaveProperty('status')
      expect(scan).toHaveProperty('progress_percent')
    })
  })
})

describe('detectionsApi', () => {
  describe('list', () => {
    it('should fetch list of detections', async () => {
      const result = await detectionsApi.list()

      expect(result.items).toBeInstanceOf(Array)
      expect(result).toHaveProperty('total')
    })

    it('should support pagination', async () => {
      const result = await detectionsApi.list({ page: 1, limit: 10 })

      expect(result.items).toBeInstanceOf(Array)
    })

    it('should filter by account ID', async () => {
      const result = await detectionsApi.list({ cloud_account_id: 'account-123' })

      expect(result.items).toBeInstanceOf(Array)
    })
  })

  describe('get', () => {
    it('should fetch detection details', async () => {
      const detection = await detectionsApi.get('detection-123')

      expect(detection).toHaveProperty('id')
      expect(detection).toHaveProperty('source_arn')
      expect(detection).toHaveProperty('health_score')
    })
  })

  describe('getMappings', () => {
    it('should fetch MITRE mappings for a detection', async () => {
      const result = await detectionsApi.getMappings('detection-123')

      expect(result.detection_id).toBe('detection-123')
      expect(result.mappings).toBeInstanceOf(Array)
      expect(result.mappings[0]).toHaveProperty('technique_id')
      expect(result.mappings[0]).toHaveProperty('confidence')
    })
  })

  describe('getSourceCounts', () => {
    it('should fetch detection source counts', async () => {
      const result = await detectionsApi.getSourceCounts()

      expect(result.counts).toBeInstanceOf(Array)
      expect(result).toHaveProperty('total')
      expect(result.counts[0]).toHaveProperty('detection_type')
      expect(result.counts[0]).toHaveProperty('count')
    })
  })
})

describe('coverageApi', () => {
  describe('get', () => {
    it('should fetch coverage data for an account', async () => {
      const coverage = await coverageApi.get('account-123')

      expect(coverage).toHaveProperty('total_techniques')
      expect(coverage).toHaveProperty('covered_techniques')
      expect(coverage).toHaveProperty('coverage_percent')
      expect(coverage).toHaveProperty('tactic_coverage')
      expect(coverage.tactic_coverage).toBeInstanceOf(Array)
    })
  })

  describe('calculate', () => {
    it('should trigger coverage calculation', async () => {
      const coverage = await coverageApi.calculate('account-123')

      expect(coverage).toHaveProperty('coverage_percent')
    })
  })

  describe('getTechniques', () => {
    it('should fetch technique coverage details', async () => {
      const techniques = await coverageApi.getTechniques('account-123')

      expect(techniques).toBeInstanceOf(Array)
      expect(techniques[0]).toHaveProperty('technique_id')
      expect(techniques[0]).toHaveProperty('status')
      expect(techniques[0]).toHaveProperty('max_confidence')
    })
  })
})

describe('credentialsApi', () => {
  describe('getSetupInstructions', () => {
    it('should fetch setup instructions for an account', async () => {
      const instructions = await credentialsApi.getSetupInstructions('account-123')

      expect(instructions).toHaveProperty('provider')
      expect(instructions).toHaveProperty('required_permissions')
      expect(instructions.required_permissions).toBeInstanceOf(Array)
      expect(instructions).toHaveProperty('manual_steps')
    })
  })

  describe('getCredential', () => {
    it('should fetch credential status', async () => {
      const credential = await credentialsApi.getCredential('account-123')

      expect(credential).toHaveProperty('status')
      expect(credential).toHaveProperty('credential_type')
    })
  })

  describe('createAWSCredential', () => {
    it('should create AWS credential', async () => {
      const credential = await credentialsApi.createAWSCredential({
        cloud_account_id: 'account-123',
        role_arn: 'arn:aws:iam::123456789012:role/A13ERole',
      })

      expect(credential.credential_type).toBe('aws_iam_role')
      expect(credential.aws_role_arn).toContain('arn:aws:iam')
    })
  })

  describe('validate', () => {
    it('should validate credentials', async () => {
      const result = await credentialsApi.validate('account-123')

      expect(result).toHaveProperty('status')
      expect(result).toHaveProperty('granted_permissions')
      expect(result).toHaveProperty('missing_permissions')
    })
  })
})

describe('gapsApi', () => {
  describe('listAcknowledged', () => {
    it('should fetch acknowledged gaps', async () => {
      const result = await gapsApi.listAcknowledged('account-123')

      expect(result).toHaveProperty('acknowledged_technique_ids')
      expect(result).toHaveProperty('count')
    })
  })

  describe('acknowledge', () => {
    it('should acknowledge a gap', async () => {
      const result = await gapsApi.acknowledge('T1078', 'account-123', 'Test notes')

      expect(result.technique_id).toBe('T1078')
      expect(result.status).toBe('acknowledged')
    })
  })
})

describe('scanStatusApi', () => {
  describe('get', () => {
    it('should fetch scan status for billing', async () => {
      const status = await scanStatusApi.get()

      expect(status).toHaveProperty('can_scan')
      expect(status).toHaveProperty('scans_used')
      expect(status).toHaveProperty('scans_allowed')
      expect(status).toHaveProperty('unlimited')
    })
  })
})
