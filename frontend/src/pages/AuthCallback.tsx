import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Shield, AlertCircle, Loader2 } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { cognitoApi } from '../services/cognitoApi'

export default function AuthCallback() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { login } = useAuth()
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

      // Validate state (CSRF protection)
      const storedState = sessionStorage.getItem('oauth_state')
      const storedCodeVerifier = sessionStorage.getItem('oauth_code_verifier')

      if (state && storedState && state !== storedState) {
        setError('Invalid state parameter. Please try again.')
        return
      }

      if (!storedCodeVerifier) {
        setError('Missing PKCE code verifier. Please try again.')
        return
      }

      // Clear stored values
      sessionStorage.removeItem('oauth_state')
      sessionStorage.removeItem('oauth_code_verifier')

      try {
        const redirectUri = `${window.location.origin}/auth/callback`
        const response = await cognitoApi.exchangeToken(code, redirectUri, storedCodeVerifier, state || undefined)

        // Store tokens via auth context
        // The login function expects email/password, so we need to handle this differently
        // Store tokens directly in localStorage
        localStorage.setItem('access_token', response.access_token)
        localStorage.setItem('refresh_token', response.refresh_token)

        // Navigate to dashboard and force reload to pick up new auth state
        window.location.href = '/dashboard'
      } catch (err: any) {
        console.error('Token exchange failed:', err)
        setError(err.response?.data?.detail || 'Authentication failed. Please try again.')
      }
    }

    handleCallback()
  }, [searchParams, navigate, login])

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full text-center">
          <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-red-100 mb-4">
            <AlertCircle className="h-6 w-6 text-red-600" />
          </div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Authentication Failed</h2>
          <p className="text-gray-600 mb-6">{error}</p>
          <button
            onClick={() => navigate('/login')}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Back to Login
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full text-center">
        <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-blue-100 mb-4">
          <Shield className="h-6 w-6 text-blue-600" />
        </div>
        <h2 className="text-xl font-semibold text-gray-900 mb-2">Completing Sign In</h2>
        <div className="flex items-center justify-center text-gray-600">
          <Loader2 className="h-5 w-5 animate-spin mr-2" />
          <span>Please wait...</span>
        </div>
      </div>
    </div>
  )
}
