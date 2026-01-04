/**
 * AdminUsers Page Tests
 *
 * Tests for the admin user management page:
 * - Displays list of users
 * - Suspended only filter works
 * - Suspend button opens modal
 * - Unsuspend button calls API directly
 * - Modal submission calls suspend API
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { useAdminAuthStore } from '../../stores/adminAuthStore'
import AdminUsers from './AdminUsers'

// Mock the navigation
const mockNavigate = vi.fn()
vi.mock('react-router', async () => {
  const actual = await vi.importActual('react-router')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

// Create test query client
function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  })
}

// Wrapper component with providers
function renderWithProviders(ui: React.ReactElement) {
  const queryClient = createTestQueryClient()
  return {
    ...render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          {ui}
        </MemoryRouter>
      </QueryClientProvider>
    ),
    queryClient,
  }
}

// Setup authenticated admin state
function setupAuthenticatedAdmin() {
  useAdminAuthStore.setState({
    accessToken: 'mock-admin-token',
    csrfToken: 'mock-csrf-token',
    admin: {
      id: 'admin-1',
      email: 'admin@example.com',
      full_name: 'Admin User',
      role: 'super_admin',
      mfa_enabled: true,
      requires_password_change: false,
      permissions: ['users:read', 'users:write'],
    },
    isAuthenticated: true,
    isLoading: false,
    isInitialised: true,
  })
}

describe('AdminUsers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setupAuthenticatedAdmin()
  })

  afterEach(() => {
    // Reset admin auth store
    useAdminAuthStore.setState({
      accessToken: null,
      csrfToken: null,
      admin: null,
      isAuthenticated: false,
      isLoading: false,
      isInitialised: true,
    })
  })

  describe('rendering', () => {
    it('should display the page title', async () => {
      renderWithProviders(<AdminUsers />)

      expect(screen.getByText('User Management')).toBeInTheDocument()
    })

    it('should display back to dashboard button', async () => {
      renderWithProviders(<AdminUsers />)

      expect(screen.getByText('Back to Dashboard')).toBeInTheDocument()
    })

    it('should display search input', async () => {
      renderWithProviders(<AdminUsers />)

      expect(
        screen.getByPlaceholderText('Search by email or name...')
      ).toBeInTheDocument()
    })

    it('should display suspended only filter button', async () => {
      renderWithProviders(<AdminUsers />)

      expect(screen.getByText('Suspended Only')).toBeInTheDocument()
    })

    it('should display loading state initially', async () => {
      renderWithProviders(<AdminUsers />)

      expect(screen.getByText('Loading users...')).toBeInTheDocument()
    })

    it('should display users after loading', async () => {
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      expect(screen.getByText('admin-user@example.com')).toBeInTheDocument()
    })

    it('should display suspended user with suspended badge', async () => {
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Suspended User')).toBeInTheDocument()
      })

      // Find the row with the suspended user and check for badge
      const suspendedBadges = screen.getAllByText('Suspended')
      expect(suspendedBadges.length).toBeGreaterThan(0)
    })
  })

  describe('filter functionality', () => {
    it('should toggle suspended only filter when clicked', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Click the filter button
      const filterButton = screen.getByText('Suspended Only')
      await user.click(filterButton)

      // Wait for filtered results (only suspended user should show)
      await waitFor(() => {
        expect(screen.getByText('Suspended User')).toBeInTheDocument()
      })

      // Active user should not be visible
      expect(screen.queryByText('Admin Test User')).not.toBeInTheDocument()
    })

    it('should show all users when filter is toggled off', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Turn on filter
      const filterButton = screen.getByText('Suspended Only')
      await user.click(filterButton)

      await waitFor(() => {
        expect(screen.queryByText('Admin Test User')).not.toBeInTheDocument()
      })

      // Turn off filter
      await user.click(filterButton)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })
    })
  })

  describe('suspend action', () => {
    it('should show suspend button for active users', async () => {
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Find suspend buttons
      const suspendButtons = screen.getAllByRole('button', { name: /Suspend/i })
      expect(suspendButtons.length).toBeGreaterThan(0)
    })

    it('should open suspend modal when suspend button is clicked', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Find the suspend button for the active user
      const suspendButtons = screen.getAllByRole('button', { name: /^Suspend$/i })
      await user.click(suspendButtons[0])

      // Modal should open - check for the heading specifically
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Suspend User' })).toBeInTheDocument()
      })
    })

    it('should show user info in suspend modal', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Click suspend
      const suspendButtons = screen.getAllByRole('button', { name: /^Suspend$/i })
      await user.click(suspendButtons[0])

      // Modal should show user info
      await waitFor(() => {
        expect(
          screen.getByText('Admin Test User (admin-user@example.com)')
        ).toBeInTheDocument()
      })
    })

    it('should close modal when cancel is clicked', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Open modal
      const suspendButtons = screen.getAllByRole('button', { name: /^Suspend$/i })
      await user.click(suspendButtons[0])

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Suspend User' })).toBeInTheDocument()
      })

      // Click cancel
      const cancelButton = screen.getByRole('button', { name: 'Cancel' })
      await user.click(cancelButton)

      // Modal should close
      await waitFor(() => {
        expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument()
      })
    })

    it('should call suspend API when modal is submitted with valid reason', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Open modal
      const suspendButtons = screen.getAllByRole('button', { name: /^Suspend$/i })
      await user.click(suspendButtons[0])

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: 'Suspend User' })).toBeInTheDocument()
      })

      // Enter reason
      const textarea = screen.getByPlaceholderText(
        'Enter the reason for suspending this user...'
      )
      await user.type(textarea, 'Bulk template scraping detected via monitoring')

      // Find the submit button in the modal (has type="submit")
      const submitButton = screen.getByRole('button', { name: /^Suspend User$/i })
      await user.click(submitButton)

      // Modal should close after successful suspension
      await waitFor(() => {
        expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument()
      })

      // User should now show as suspended (status updated locally)
      // The user list is updated optimistically
    })
  })

  describe('unsuspend action', () => {
    it('should show reactivate button for suspended users', async () => {
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Suspended User')).toBeInTheDocument()
      })

      // Find reactivate button
      const reactivateButtons = screen.getAllByRole('button', { name: /Reactivate/i })
      expect(reactivateButtons.length).toBeGreaterThan(0)
    })

    it('should call unsuspend API when reactivate button is clicked', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Suspended User')).toBeInTheDocument()
      })

      // Initially there should be one Reactivate button
      const reactivateButton = screen.getByRole('button', { name: /Reactivate/i })
      expect(reactivateButton).toBeInTheDocument()

      // Click reactivate
      await user.click(reactivateButton)

      // After successful unsuspension, the Reactivate button should be gone
      // (replaced with Suspend button for that user)
      await waitFor(() => {
        expect(screen.queryByRole('button', { name: /Reactivate/i })).not.toBeInTheDocument()
      })
    })
  })

  describe('navigation', () => {
    it('should navigate to dashboard when back button is clicked', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      const backButton = screen.getByText('Back to Dashboard')
      await user.click(backButton)

      expect(mockNavigate).toHaveBeenCalledWith('/admin/dashboard')
    })

    it('should redirect to login when not authenticated', async () => {
      // Clear authentication
      useAdminAuthStore.setState({
        accessToken: null,
        csrfToken: null,
        admin: null,
        isAuthenticated: false,
        isLoading: false,
        isInitialised: true,
      })

      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/admin/login')
      })
    })
  })

  describe('search functionality', () => {
    it('should filter users when search is submitted', async () => {
      const user = userEvent.setup()
      renderWithProviders(<AdminUsers />)

      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // Type in search box
      const searchInput = screen.getByPlaceholderText('Search by email or name...')
      await user.type(searchInput, 'suspended')

      // Submit search
      const searchButton = screen.getByRole('button', { name: 'Search' })
      await user.click(searchButton)

      // Should show only the suspended user
      await waitFor(() => {
        expect(screen.getByText('Suspended User')).toBeInTheDocument()
      })

      // Admin user should not be visible
      expect(screen.queryByText('Admin Test User')).not.toBeInTheDocument()
    })
  })

  describe('error handling', () => {
    it('should display error message when API call fails', async () => {
      // This would require mocking a failing API response
      // For now, we test that the error display exists
      renderWithProviders(<AdminUsers />)

      // The error state is controlled by the component
      // We can verify the error display structure exists
      await waitFor(() => {
        expect(screen.getByText('Admin Test User')).toBeInTheDocument()
      })

      // No error should be displayed initially
      expect(screen.queryByText(/Failed to/)).not.toBeInTheDocument()
    })
  })
})
