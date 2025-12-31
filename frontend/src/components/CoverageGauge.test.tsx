/**
 * CoverageGauge Component Tests
 *
 * Tests for the circular gauge component that displays coverage percentage:
 * - Displays correct percentage value
 * - Shows appropriate status labels (Strong, Moderate, Needs Work)
 * - Uses correct colours for different coverage levels
 * - Displays confidence value correctly
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import CoverageGauge from './CoverageGauge'

describe('CoverageGauge', () => {
  describe('percentage display', () => {
    it('should display the percentage value with one decimal place', () => {
      render(<CoverageGauge percent={45.678} confidence={0.75} />)

      expect(screen.getByText('45.7%')).toBeInTheDocument()
    })

    it('should display 0% correctly', () => {
      render(<CoverageGauge percent={0} confidence={0} />)

      expect(screen.getByText('0.0%')).toBeInTheDocument()
    })

    it('should display 100% correctly', () => {
      render(<CoverageGauge percent={100} confidence={1} />)

      expect(screen.getByText('100.0%')).toBeInTheDocument()
    })
  })

  describe('status labels', () => {
    it('should show "Strong" for coverage >= 70%', () => {
      render(<CoverageGauge percent={75} confidence={0.8} />)

      expect(screen.getByText('Strong')).toBeInTheDocument()
    })

    it('should show "Strong" at exactly 70%', () => {
      render(<CoverageGauge percent={70} confidence={0.7} />)

      expect(screen.getByText('Strong')).toBeInTheDocument()
    })

    it('should show "Moderate" for coverage >= 40% and < 70%', () => {
      render(<CoverageGauge percent={55} confidence={0.6} />)

      expect(screen.getByText('Moderate')).toBeInTheDocument()
    })

    it('should show "Moderate" at exactly 40%', () => {
      render(<CoverageGauge percent={40} confidence={0.5} />)

      expect(screen.getByText('Moderate')).toBeInTheDocument()
    })

    it('should show "Needs Work" for coverage < 40%', () => {
      render(<CoverageGauge percent={25} confidence={0.4} />)

      expect(screen.getByText('Needs Work')).toBeInTheDocument()
    })

    it('should show "Needs Work" at exactly 39%', () => {
      render(<CoverageGauge percent={39} confidence={0.4} />)

      expect(screen.getByText('Needs Work')).toBeInTheDocument()
    })
  })

  describe('confidence display', () => {
    it('should display confidence as percentage', () => {
      render(<CoverageGauge percent={50} confidence={0.75} />)

      expect(screen.getByText('75%')).toBeInTheDocument()
    })

    it('should display confidence label', () => {
      render(<CoverageGauge percent={50} confidence={0.85} />)

      expect(screen.getByText(/Confidence:/)).toBeInTheDocument()
    })

    it('should round confidence to nearest integer', () => {
      render(<CoverageGauge percent={50} confidence={0.666} />)

      expect(screen.getByText('67%')).toBeInTheDocument()
    })

    it('should handle 0 confidence', () => {
      render(<CoverageGauge percent={50} confidence={0} />)

      expect(screen.getByText('0%')).toBeInTheDocument()
    })

    it('should handle 100% confidence', () => {
      render(<CoverageGauge percent={50} confidence={1} />)

      expect(screen.getByText('100%')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    it('should include Detection Coverage label', () => {
      render(<CoverageGauge percent={50} confidence={0.7} />)

      expect(screen.getByText('Detection Coverage')).toBeInTheDocument()
    })
  })

  describe('SVG rendering', () => {
    it('should render SVG element', () => {
      const { container } = render(<CoverageGauge percent={50} confidence={0.7} />)

      const svg = container.querySelector('svg')
      expect(svg).toBeInTheDocument()
    })

    it('should have two circle elements (background and progress)', () => {
      const { container } = render(<CoverageGauge percent={50} confidence={0.7} />)

      const circles = container.querySelectorAll('circle')
      expect(circles.length).toBe(2)
    })
  })

  describe('edge cases', () => {
    it('should handle negative percentage', () => {
      render(<CoverageGauge percent={-10} confidence={0.5} />)

      expect(screen.getByText('-10.0%')).toBeInTheDocument()
      expect(screen.getByText('Needs Work')).toBeInTheDocument()
    })

    it('should handle percentage over 100', () => {
      render(<CoverageGauge percent={120} confidence={0.9} />)

      expect(screen.getByText('120.0%')).toBeInTheDocument()
      expect(screen.getByText('Strong')).toBeInTheDocument()
    })
  })
})
