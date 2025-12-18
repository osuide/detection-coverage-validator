import { useState, useEffect } from 'react'
import { cognitoApi, CognitoConfig } from '../services/cognitoApi'

interface SocialLoginButtonsProps {
  onError?: (error: string) => void
  mode?: 'login' | 'signup'
}

export default function SocialLoginButtons({ onError, mode = 'login' }: SocialLoginButtonsProps) {
  const [config, setConfig] = useState<CognitoConfig | null>(null)
  const [loading, setLoading] = useState<string | null>(null)

  useEffect(() => {
    cognitoApi.getConfig()
      .then(setConfig)
      .catch(() => {
        // SSO not configured - don't show buttons
        setConfig({ configured: false, providers: [] })
      })
  }, [])

  const handleSocialLogin = async (provider: string) => {
    if (loading) return

    setLoading(provider)
    try {
      const redirectUri = `${window.location.origin}/auth/callback`
      const response = await cognitoApi.initiateSso(provider, redirectUri)

      // Store state for CSRF validation
      sessionStorage.setItem('oauth_state', response.state)

      // Redirect to provider
      window.location.href = response.authorization_url
    } catch (err) {
      onError?.('Failed to initiate SSO. Please try again.')
      setLoading(null)
    }
  }

  // Don't render if SSO is not configured
  if (!config?.configured) {
    return null
  }

  const hasGoogle = config.providers.includes('Google')

  if (!hasGoogle) {
    return null
  }

  return (
    <div className="space-y-3">
      <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-gray-300" />
        </div>
        <div className="relative flex justify-center text-sm">
          <span className="px-2 bg-white text-gray-500">Or continue with</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {hasGoogle && (
          <button
            type="button"
            onClick={() => handleSocialLogin('google')}
            disabled={!!loading}
            className="w-full inline-flex justify-center items-center py-2.5 px-4 border border-gray-300 rounded-lg shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading === 'google' ? (
              <svg className="animate-spin h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            ) : (
              <>
                <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                  />
                </svg>
                {mode === 'signup' ? 'Sign up with Google' : 'Continue with Google'}
              </>
            )}
          </button>
        )}
      </div>
    </div>
  )
}
