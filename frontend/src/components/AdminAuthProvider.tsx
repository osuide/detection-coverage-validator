/**
 * Admin Auth Provider
 *
 * Handles session restoration for admin portal on page load.
 * Wraps admin routes to ensure auth state is initialised before rendering.
 */

import { useEffect, ReactNode } from 'react'
import { useAdminAuthStore, adminAuthActions } from '../stores/adminAuthStore'

interface AdminAuthProviderProps {
  children: ReactNode
}

export function AdminAuthProvider({ children }: AdminAuthProviderProps) {
  const { isInitialised } = useAdminAuthStore()

  useEffect(() => {
    // Only restore session once
    if (!isInitialised) {
      adminAuthActions.restoreSession()
    }
  }, [isInitialised])

  // Show loading state while restoring session
  if (!isInitialised) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500"></div>
      </div>
    )
  }

  return <>{children}</>
}

export default AdminAuthProvider
