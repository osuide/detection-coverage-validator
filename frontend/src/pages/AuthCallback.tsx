import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { Shield, AlertCircle, Loader2 } from 'lucide-react'
import { useAuthStore } from '../stores/authStore'
import { cognitoApi } from '../services/cognitoApi'
import { githubApi } from '../services/githubApi'

export default function AuthCallback() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const handleCallback = async () => {
      const code = searchParams.get('code')
      const state = searchParams.get('state')
      const errorParam = searchParams.get('error')
      const errorDescription = searchParams.get('error_description')

      // Handle error from provider
      if (errorParam) {
        setError(errorDescription || errorParam)
        return
      }

      // Validate code
      if (!code) {
        setError('No authorization code received')
        return
      }

      // Get stored OAuth info
      const storedState = sessionStorage.getItem('oauth_state')
      const storedProvider = sessionStorage.getItem('oauth_provider') || 'cognito'
      const storedCodeVerifier = sessionStorage.getItem('oauth_code_verifier')

      // Validate state (CSRF protection)
      if (state && storedState && state !== storedState) {
        setError('Invalid state parameter. Please try again.')
        return
      }

      // Clear stored values
      sessionStorage.removeItem('oauth_state')
      sessionStorage.removeItem('oauth_provider')
      sessionStorage.removeItem('oauth_code_verifier')

      try {
        const redirectUri = `${window.location.origin}/auth/callback`
        let response

        if (storedProvider === 'github') {
          // Direct GitHub OAuth
          response = await githubApi.exchangeToken(code, redirectUri, state || '')
        } else {
          // Cognito OAuth (Google)
          if (!storedCodeVerifier) {
            setError('Missing PKCE code verifier. Please try again.')
            return
          }

          response = await cognitoApi.exchangeToken(code, redirectUri, storedCodeVerifier, state || undefined)
        }

        // Update Zustand store with auth data (cookies are set by backend)
        setAuth({
          accessToken: response.access_token,
          csrfToken: response.csrf_token,
          user: response.user,
          organization: response.organization,
        })

        // Navigate to dashboard (no reload needed - Zustand is in memory)
        navigate('/dashboard', { replace: true })
      } catch (err: any) {
        console.error('Token exchange failed:', err)
        setError(err.response?.data?.detail || 'Authentication failed. Please try again.')
      }
    }

    handleCallback()
  }, [searchParams, navigate, setAuth])

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full text-center">
          <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-red-900/30 mb-4">
            <AlertCircle className="h-6 w-6 text-red-400" />
          </div>
          <h2 className="text-xl font-semibold text-white mb-2">Authentication Failed</h2>
          <p className="text-gray-300 mb-6">{error}</p>
          <button
            onClick={() => navigate('/login')}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-xs text-white bg-blue-600 hover:bg-blue-700 focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Back to Login
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full text-center">
        <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-blue-900/30 mb-4">
          <Shield className="h-6 w-6 text-blue-400" />
        </div>
        <h2 className="text-xl font-semibold text-white mb-2">Completing Sign In</h2>
        <div className="flex items-center justify-center text-gray-300">
          <Loader2 className="h-5 w-5 animate-spin mr-2" />
          <span>Please wait...</span>
        </div>
      </div>
    </div>
  )
}
