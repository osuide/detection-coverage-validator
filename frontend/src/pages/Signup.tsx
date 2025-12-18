import { useState, FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import A13ELogo from '../components/A13ELogo'

export default function Signup() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [organizationName, setOrganizationName] = useState('')
  const [termsAccepted, setTermsAccepted] = useState(false)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  // Password validation state
  const [passwordValidation, setPasswordValidation] = useState({
    length: false,
    lowercase: false,
    uppercase: false,
    number: false,
    special: false,
  })

  const { signup } = useAuth()
  const navigate = useNavigate()

  const validatePassword = (pwd: string) => {
    setPasswordValidation({
      length: pwd.length >= 12,
      lowercase: /[a-z]/.test(pwd),
      uppercase: /[A-Z]/.test(pwd),
      number: /\d/.test(pwd),
      special: /[@$!%*?&]/.test(pwd),
    })
  }

  const isPasswordValid = Object.values(passwordValidation).every(Boolean)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')

    if (!termsAccepted) {
      setError('You must accept the terms of service')
      return
    }

    if (!isPasswordValid) {
      setError('Password does not meet requirements')
      return
    }

    setIsLoading(true)

    try {
      await signup(email, password, fullName, organizationName)
      navigate('/dashboard', { replace: true })
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message :
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        'Signup failed. Please try again.'
      setError(errorMessage)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="flex justify-center">
            <A13ELogo size="lg" showTagline />
          </div>
          <h2 className="mt-8 text-center text-3xl font-extrabold text-white">
            Create your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-400">
            Start analyzing your detection coverage today
          </p>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          {error && (
            <div className="bg-red-900/50 border border-red-500 text-red-200 px-4 py-3 rounded">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="fullName" className="block text-sm font-medium text-gray-300">
                Full Name
              </label>
              <input
                id="fullName"
                name="fullName"
                type="text"
                autoComplete="name"
                required
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-700 bg-gray-800 text-white placeholder-gray-500 rounded-md focus:outline-none focus:ring-cyan-500 focus:border-cyan-500 focus:z-10 sm:text-sm"
                placeholder="John Doe"
              />
            </div>

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-300">
                Work Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-700 bg-gray-800 text-white placeholder-gray-500 rounded-md focus:outline-none focus:ring-cyan-500 focus:border-cyan-500 focus:z-10 sm:text-sm"
                placeholder="you@company.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                required
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value)
                  validatePassword(e.target.value)
                }}
                className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-700 bg-gray-800 text-white placeholder-gray-500 rounded-md focus:outline-none focus:ring-cyan-500 focus:border-cyan-500 focus:z-10 sm:text-sm"
                placeholder="Create a strong password"
              />
              <div className="mt-2 text-xs space-y-1">
                <div className={passwordValidation.length ? 'text-green-400' : 'text-gray-500'}>
                  {passwordValidation.length ? '\u2713' : '\u25cb'} 12+ characters
                </div>
                <div className={passwordValidation.lowercase ? 'text-green-400' : 'text-gray-500'}>
                  {passwordValidation.lowercase ? '\u2713' : '\u25cb'} Lowercase letter
                </div>
                <div className={passwordValidation.uppercase ? 'text-green-400' : 'text-gray-500'}>
                  {passwordValidation.uppercase ? '\u2713' : '\u25cb'} Uppercase letter
                </div>
                <div className={passwordValidation.number ? 'text-green-400' : 'text-gray-500'}>
                  {passwordValidation.number ? '\u2713' : '\u25cb'} Number
                </div>
                <div className={passwordValidation.special ? 'text-green-400' : 'text-gray-500'}>
                  {passwordValidation.special ? '\u2713' : '\u25cb'} Special character (@$!%*?&)
                </div>
              </div>
            </div>

            <div>
              <label htmlFor="organizationName" className="block text-sm font-medium text-gray-300">
                Organization Name
              </label>
              <input
                id="organizationName"
                name="organizationName"
                type="text"
                required
                value={organizationName}
                onChange={(e) => setOrganizationName(e.target.value)}
                className="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-700 bg-gray-800 text-white placeholder-gray-500 rounded-md focus:outline-none focus:ring-cyan-500 focus:border-cyan-500 focus:z-10 sm:text-sm"
                placeholder="Acme Security Inc"
              />
            </div>
          </div>

          <div className="flex items-center">
            <input
              id="terms"
              name="terms"
              type="checkbox"
              checked={termsAccepted}
              onChange={(e) => setTermsAccepted(e.target.checked)}
              className="h-4 w-4 text-cyan-600 focus:ring-cyan-500 border-gray-700 bg-gray-800 rounded"
            />
            <label htmlFor="terms" className="ml-2 block text-sm text-gray-400">
              I agree to the{' '}
              <a href="#" className="text-cyan-400 hover:text-cyan-300">
                Terms of Service
              </a>{' '}
              and{' '}
              <a href="#" className="text-cyan-400 hover:text-cyan-300">
                Privacy Policy
              </a>
            </label>
          </div>

          <div>
            <button
              type="submit"
              disabled={isLoading || !isPasswordValid || !termsAccepted}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-cyan-600 hover:bg-cyan-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <span className="flex items-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Creating account...
                </span>
              ) : (
                'Create Account'
              )}
            </button>
          </div>
        </form>

        <p className="mt-2 text-center text-sm text-gray-400">
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-cyan-400 hover:text-cyan-300">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  )
}
