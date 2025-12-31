/**
 * Test Utilities
 *
 * Custom render function and utilities for testing React components
 * with all necessary providers (React Query, Router, Auth, etc.)
 */

import { ReactElement, ReactNode } from 'react'
import { render, RenderOptions } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, MemoryRouter } from 'react-router'
import { AuthProvider } from '../contexts/AuthContext'
import { useAuthStore } from '../stores/authStore'

// Create a fresh QueryClient for each test
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

interface WrapperProps {
  children: ReactNode
}

interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialEntries?: string[]
  useMemoryRouter?: boolean
  withAuth?: boolean
  authState?: Partial<{
    accessToken: string | null
    user: {
      id: string
      email: string
      full_name: string
      mfa_enabled: boolean
    } | null
    organization: {
      id: string
      name: string
      slug: string
      plan: string
    } | null
    isAuthenticated: boolean
    isLoading: boolean
    isInitialised: boolean
  }>
}

/**
 * Set up auth state for testing
 */
function setupAuthState(authState: CustomRenderOptions['authState']) {
  useAuthStore.setState({
    accessToken: authState?.accessToken ?? null,
    csrfToken: authState?.accessToken ? 'test-csrf' : null,
    user: authState?.user ?? null,
    organization: authState?.organization ?? null,
    isAuthenticated: authState?.isAuthenticated ?? false,
    isLoading: authState?.isLoading ?? false,
    isInitialised: authState?.isInitialised ?? true,
  })
}

/**
 * Custom render function that wraps components with all necessary providers
 */
function customRender(
  ui: ReactElement,
  options: CustomRenderOptions = {}
) {
  const {
    initialEntries = ['/'],
    useMemoryRouter = false,
    withAuth = false,
    authState,
    ...renderOptions
  } = options

  // Set up auth state before rendering if provided
  if (authState) {
    setupAuthState(authState)
  }

  const queryClient = createTestQueryClient()

  function Wrapper({ children }: WrapperProps) {
    const Router = useMemoryRouter ? MemoryRouter : BrowserRouter
    const routerProps = useMemoryRouter ? { initialEntries } : {}

    const content = (
      <QueryClientProvider client={queryClient}>
        <Router {...routerProps}>
          {children}
        </Router>
      </QueryClientProvider>
    )

    if (withAuth) {
      return (
        <QueryClientProvider client={queryClient}>
          <Router {...routerProps}>
            <AuthProvider>
              {children}
            </AuthProvider>
          </Router>
        </QueryClientProvider>
      )
    }

    return content
  }

  return {
    ...render(ui, { wrapper: Wrapper, ...renderOptions }),
    queryClient,
  }
}

/**
 * Render without router (for components that don't need routing)
 */
function renderWithQueryClient(
  ui: ReactElement,
  options: Omit<RenderOptions, 'wrapper'> = {}
) {
  const queryClient = createTestQueryClient()

  function Wrapper({ children }: WrapperProps) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    )
  }

  return {
    ...render(ui, { wrapper: Wrapper, ...options }),
    queryClient,
  }
}

/**
 * Helper to create mock authenticated state
 */
function createMockAuthState(overrides?: Partial<CustomRenderOptions['authState']>) {
  return {
    accessToken: 'mock-token',
    user: {
      id: 'user-123',
      email: 'test@example.com',
      full_name: 'Test User',
      mfa_enabled: false,
    },
    organization: {
      id: 'org-123',
      name: 'Test Organization',
      slug: 'test-org',
      plan: 'free',
    },
    isAuthenticated: true,
    isLoading: false,
    isInitialised: true,
    ...overrides,
  }
}

/**
 * Helper to create mock unauthenticated state
 */
function createMockUnauthState() {
  return {
    accessToken: null,
    user: null,
    organization: null,
    isAuthenticated: false,
    isLoading: false,
    isInitialised: true,
  }
}

// Re-export everything from testing-library
export * from '@testing-library/react'
export { default as userEvent } from '@testing-library/user-event'

// Export custom renders and helpers
export {
  customRender as render,
  renderWithQueryClient,
  createTestQueryClient,
  setupAuthState,
  createMockAuthState,
  createMockUnauthState,
}
