/**
 * useTokenRefresh - Proactive Token Refresh Hook
 *
 * This hook implements proactive token refresh to prevent unexpected logouts:
 * - Refreshes tokens before they expire (not just on 401)
 * - Refreshes on tab focus (handles long idle periods)
 * - Syncs CSRF tokens across tabs via cookie
 *
 * Security considerations:
 * - Token refresh happens 5 minutes before expiry
 * - Visibility-based refresh prevents stale tokens after sleep/hibernate
 * - CSRF token is always read fresh from cookie before refresh
 */

import { useEffect, useRef, useCallback } from 'react'
import { useAuthStore, authActions } from '../stores/authStore'

// Token expires in 30 minutes, refresh 5 minutes before
const TOKEN_REFRESH_INTERVAL_MS = 25 * 60 * 1000 // 25 minutes
// Minimum time between refreshes to prevent hammering
const MIN_REFRESH_INTERVAL_MS = 30 * 1000 // 30 seconds

/**
 * Helper to get CSRF token from cookie (for cross-tab sync)
 */
function getCsrfTokenFromCookie(): string | null {
  const match = document.cookie.match(/dcv_csrf_token=([^;]+)/)
  return match ? match[1] : null
}

/**
 * Hook that handles proactive token refresh
 */
export function useTokenRefresh() {
  const { isAuthenticated, accessToken } = useAuthStore()
  const lastRefreshRef = useRef<number>(Date.now())
  const refreshIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  /**
   * Perform token refresh with rate limiting
   */
  const performRefresh = useCallback(async (force: boolean = false) => {
    const now = Date.now()
    const timeSinceLastRefresh = now - lastRefreshRef.current

    // Rate limit refreshes unless forced
    if (!force && timeSinceLastRefresh < MIN_REFRESH_INTERVAL_MS) {
      return
    }

    // Sync CSRF token from cookie before refresh (handles cross-tab updates)
    const cookieCsrf = getCsrfTokenFromCookie()
    const storeCsrf = useAuthStore.getState().csrfToken

    if (cookieCsrf && cookieCsrf !== storeCsrf) {
      // Cookie was updated by another tab, sync it
      useAuthStore.getState().setCsrfToken(cookieCsrf)
    }

    try {
      const newToken = await authActions.refreshToken()
      if (newToken) {
        lastRefreshRef.current = Date.now()
      }
    } catch {
      // Refresh failed - authActions.refreshToken already handles clearing auth
    }
  }, [])

  /**
   * Handle visibility change (tab focus/blur)
   */
  const handleVisibilityChange = useCallback(() => {
    if (document.visibilityState === 'visible' && isAuthenticated) {
      // Tab became visible - refresh token if it's been a while
      const timeSinceLastRefresh = Date.now() - lastRefreshRef.current

      // If more than half the refresh interval has passed, refresh now
      if (timeSinceLastRefresh > TOKEN_REFRESH_INTERVAL_MS / 2) {
        performRefresh(true)
      }
    }
  }, [isAuthenticated, performRefresh])

  /**
   * Set up periodic refresh and visibility listeners
   */
  useEffect(() => {
    if (!isAuthenticated || !accessToken) {
      // Clear interval if not authenticated
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current)
        refreshIntervalRef.current = null
      }
      return
    }

    // Set up periodic refresh
    refreshIntervalRef.current = setInterval(() => {
      performRefresh(false)
    }, TOKEN_REFRESH_INTERVAL_MS)

    // Set up visibility change listener
    document.addEventListener('visibilitychange', handleVisibilityChange)

    // Mark initial authentication time
    lastRefreshRef.current = Date.now()

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current)
        refreshIntervalRef.current = null
      }
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [isAuthenticated, accessToken, performRefresh, handleVisibilityChange])

  /**
   * Handle online/offline events
   */
  useEffect(() => {
    const handleOnline = () => {
      if (isAuthenticated) {
        // Just came back online - refresh token
        performRefresh(true)
      }
    }

    window.addEventListener('online', handleOnline)

    return () => {
      window.removeEventListener('online', handleOnline)
    }
  }, [isAuthenticated, performRefresh])

  return {
    refreshNow: () => performRefresh(true),
  }
}

export default useTokenRefresh
