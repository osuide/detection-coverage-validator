import { useEffect } from 'react'
import { useLocation } from 'react-router'

/**
 * ScrollToTop component - scrolls to top of page on route change.
 * Place this inside the Router but outside Routes.
 */
export default function ScrollToTop() {
  const { pathname } = useLocation()

  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])

  return null
}
