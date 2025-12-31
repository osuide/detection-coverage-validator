/**
 * ProtectedRoute Component Tests
 *
 * Tests for the authentication guard component.
 * Note: These tests use a mock of useAuth to avoid complex AuthProvider setup
 * which can cause memory issues in the test environment.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ProtectedRoute from './ProtectedRoute'

// Mock the useAuth hook
vi.mock('../contexts/AuthContext', () => ({
  useAuth: vi.fn(),
}))

import { useAuth } from '../contexts/AuthContext'

const mockUseAuth = useAuth as ReturnType<typeof vi.fn>

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('when loading', () => {
    it('should show loading spinner', () => {
      mockUseAuth.mockReturnValue({
        isAuthenticated: false,
        isLoading: true,
      })

      render(
        <MemoryRouter initialEntries={['/dashboard']}>
          <ProtectedRoute>
            <div>Protected Content</div>
          </ProtectedRoute>
        </MemoryRouter>
      )

      expect(screen.getByText('Loading...')).toBeInTheDocument()
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })
  })

  describe('when unauthenticated', () => {
    it('should not render children', () => {
      mockUseAuth.mockReturnValue({
        isAuthenticated: false,
        isLoading: false,
      })

      render(
        <MemoryRouter initialEntries={['/dashboard']}>
          <ProtectedRoute>
            <div>Protected Content</div>
          </ProtectedRoute>
        </MemoryRouter>
      )

      // Content should not be visible (redirected to login)
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
    })
  })

  describe('when authenticated', () => {
    it('should render children', () => {
      mockUseAuth.mockReturnValue({
        isAuthenticated: true,
        isLoading: false,
      })

      render(
        <MemoryRouter initialEntries={['/dashboard']}>
          <ProtectedRoute>
            <div>Protected Content</div>
          </ProtectedRoute>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('should render complex children', () => {
      mockUseAuth.mockReturnValue({
        isAuthenticated: true,
        isLoading: false,
      })

      render(
        <MemoryRouter initialEntries={['/dashboard']}>
          <ProtectedRoute>
            <div>
              <h1>Dashboard</h1>
              <p>Welcome back, user!</p>
              <button>Action</button>
            </div>
          </ProtectedRoute>
        </MemoryRouter>
      )

      expect(screen.getByText('Dashboard')).toBeInTheDocument()
      expect(screen.getByText('Welcome back, user!')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Action' })).toBeInTheDocument()
    })
  })
})
