/**
 * TacticHeatmap Component Tests
 *
 * Tests for the MITRE ATT&CK tactic coverage heatmap:
 * - Renders all tactics correctly
 * - Sorts tactics in official MITRE ATT&CK order
 * - Applies correct colours based on coverage percentage
 * - Displays coverage counts and percentages
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import TacticHeatmap from './TacticHeatmap'
import { TacticCoverage } from '../services/api'

// Helper to create mock tactic data
function createMockTactic(overrides: Partial<TacticCoverage> = {}): TacticCoverage {
  return {
    tactic_id: 'TA0001',
    tactic_name: 'Initial Access',
    covered: 5,
    partial: 2,
    uncovered: 3,
    total: 10,
    percent: 50,
    ...overrides,
  }
}

describe('TacticHeatmap', () => {
  describe('rendering', () => {
    it('should render all tactics', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', tactic_name: 'Initial Access' }),
        createMockTactic({ tactic_id: 'TA0002', tactic_name: 'Execution' }),
        createMockTactic({ tactic_id: 'TA0003', tactic_name: 'Persistence' }),
      ]

      render(<TacticHeatmap tactics={tactics} />)

      expect(screen.getByText('Initial Access')).toBeInTheDocument()
      expect(screen.getByText('Execution')).toBeInTheDocument()
      expect(screen.getByText('Persistence')).toBeInTheDocument()
    })

    it('should display coverage counts', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({
          tactic_id: 'TA0001',
          tactic_name: 'Initial Access',
          covered: 7,
          total: 15,
        }),
      ]

      render(<TacticHeatmap tactics={tactics} />)

      expect(screen.getByText('7/15')).toBeInTheDocument()
    })

    it('should display percentage', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({
          tactic_id: 'TA0001',
          tactic_name: 'Initial Access',
          percent: 46.7,
        }),
      ]

      render(<TacticHeatmap tactics={tactics} />)

      // Percentage is rounded to integer
      expect(screen.getByText('(47%)')).toBeInTheDocument()
    })

    it('should handle empty tactics array', () => {
      const { container } = render(<TacticHeatmap tactics={[]} />)

      // Should render empty container
      expect(container.querySelector('.space-y-2')).toBeInTheDocument()
    })
  })

  describe('tactic ordering', () => {
    it('should sort tactics in MITRE ATT&CK order', () => {
      // Provide tactics in wrong order
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0040', tactic_name: 'Impact' }),
        createMockTactic({ tactic_id: 'TA0001', tactic_name: 'Initial Access' }),
        createMockTactic({ tactic_id: 'TA0005', tactic_name: 'Defense Evasion' }),
      ]

      render(<TacticHeatmap tactics={tactics} />)

      const tacticNames = screen.getAllByText(/Initial Access|Defense Evasion|Impact/)

      // Check order: Initial Access (TA0001) < Defense Evasion (TA0005) < Impact (TA0040)
      expect(tacticNames[0]).toHaveTextContent('Initial Access')
      expect(tacticNames[1]).toHaveTextContent('Defense Evasion')
      expect(tacticNames[2]).toHaveTextContent('Impact')
    })

    it('should handle unknown tactics by placing them at the end', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA9999', tactic_name: 'Unknown Tactic' }),
        createMockTactic({ tactic_id: 'TA0001', tactic_name: 'Initial Access' }),
      ]

      render(<TacticHeatmap tactics={tactics} />)

      const tacticNames = screen.getAllByText(/Initial Access|Unknown Tactic/)

      expect(tacticNames[0]).toHaveTextContent('Initial Access')
      expect(tacticNames[1]).toHaveTextContent('Unknown Tactic')
    })
  })

  describe('colour coding', () => {
    it('should use green colour for coverage >= 70%', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 75 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('.bg-green-500')
      expect(progressBar).toBeInTheDocument()
    })

    it('should use yellow colour for coverage >= 40% and < 70%', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 55 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('.bg-yellow-500')
      expect(progressBar).toBeInTheDocument()
    })

    it('should use orange colour for coverage > 0% and < 40%', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 20 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('.bg-orange-500')
      expect(progressBar).toBeInTheDocument()
    })

    it('should use gray colour for 0% coverage', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 0 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('.bg-gray-600')
      expect(progressBar).toBeInTheDocument()
    })

    it('should use green at exactly 70%', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 70 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('.bg-green-500')
      expect(progressBar).toBeInTheDocument()
    })

    it('should use yellow at exactly 40%', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 40 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('.bg-yellow-500')
      expect(progressBar).toBeInTheDocument()
    })
  })

  describe('progress bar width', () => {
    it('should set correct width based on percentage', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 65 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('[style*="width: 65%"]')
      expect(progressBar).toBeInTheDocument()
    })

    it('should handle 0% width', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 0 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('[style*="width: 0%"]')
      expect(progressBar).toBeInTheDocument()
    })

    it('should handle 100% width', () => {
      const tactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', percent: 100 }),
      ]

      const { container } = render(<TacticHeatmap tactics={tactics} />)

      const progressBar = container.querySelector('[style*="width: 100%"]')
      expect(progressBar).toBeInTheDocument()
    })
  })

  describe('full 12-tactic coverage', () => {
    it('should render all 12 cloud-relevant MITRE tactics', () => {
      const allTactics: TacticCoverage[] = [
        createMockTactic({ tactic_id: 'TA0001', tactic_name: 'Initial Access', percent: 50 }),
        createMockTactic({ tactic_id: 'TA0002', tactic_name: 'Execution', percent: 45 }),
        createMockTactic({ tactic_id: 'TA0003', tactic_name: 'Persistence', percent: 60 }),
        createMockTactic({ tactic_id: 'TA0004', tactic_name: 'Privilege Escalation', percent: 55 }),
        createMockTactic({ tactic_id: 'TA0005', tactic_name: 'Defense Evasion', percent: 40 }),
        createMockTactic({ tactic_id: 'TA0006', tactic_name: 'Credential Access', percent: 35 }),
        createMockTactic({ tactic_id: 'TA0007', tactic_name: 'Discovery', percent: 70 }),
        createMockTactic({ tactic_id: 'TA0008', tactic_name: 'Lateral Movement', percent: 25 }),
        createMockTactic({ tactic_id: 'TA0009', tactic_name: 'Collection', percent: 30 }),
        createMockTactic({ tactic_id: 'TA0010', tactic_name: 'Exfiltration', percent: 20 }),
        createMockTactic({ tactic_id: 'TA0011', tactic_name: 'Command and Control', percent: 15 }),
        createMockTactic({ tactic_id: 'TA0040', tactic_name: 'Impact', percent: 80 }),
      ]

      render(<TacticHeatmap tactics={allTactics} />)

      // Verify all 12 tactics are rendered
      expect(screen.getByText('Initial Access')).toBeInTheDocument()
      expect(screen.getByText('Execution')).toBeInTheDocument()
      expect(screen.getByText('Persistence')).toBeInTheDocument()
      expect(screen.getByText('Privilege Escalation')).toBeInTheDocument()
      expect(screen.getByText('Defense Evasion')).toBeInTheDocument()
      expect(screen.getByText('Credential Access')).toBeInTheDocument()
      expect(screen.getByText('Discovery')).toBeInTheDocument()
      expect(screen.getByText('Lateral Movement')).toBeInTheDocument()
      expect(screen.getByText('Collection')).toBeInTheDocument()
      expect(screen.getByText('Exfiltration')).toBeInTheDocument()
      expect(screen.getByText('Command and Control')).toBeInTheDocument()
      expect(screen.getByText('Impact')).toBeInTheDocument()
    })
  })
})
