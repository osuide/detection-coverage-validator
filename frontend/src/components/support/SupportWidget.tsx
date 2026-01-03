import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router'
import {
  MessageSquare,
  X,
  Send,
  Loader2,
  FileText,
  AlertTriangle
} from 'lucide-react'
import { clsx } from 'clsx'
import { supportApi, UserSupportContext } from '../../services/supportApi'
import { useAuth } from '../../contexts/AuthContext'

/**
 * User documentation URL.
 *
 * URL Structure:
 * - User docs: /docs on the same origin (staging.a13e.com/docs, app.a13e.com/docs)
 * - OpenAPI specs: separate subdomain (docs.staging.a13e.com, docs.a13e.com)
 *
 * We use a relative path so it works in all environments.
 */
const USER_DOCS_URL = '/docs'

export default function SupportWidget() {
  const { user } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [isOpen, setIsOpen] = useState(false)
  const [mode, setMode] = useState<'menu' | 'ticket' | 'success'>('menu')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [context, setContext] = useState<UserSupportContext | null>(null)
  const [ticketId, setTicketId] = useState<string | null>(null)

  // Form State
  const [subject, setSubject] = useState('')
  const [description, setDescription] = useState('')
  const [category, setCategory] = useState('technical')
  const [cloudProvider, setCloudProvider] = useState<string>('')
  const [errors, setErrors] = useState<{ subject?: string; description?: string }>({})
  const [submitError, setSubmitError] = useState<string | null>(null)

  // Validation constants (must match backend)
  const SUBJECT_MIN = 5
  const SUBJECT_MAX = 200
  const DESCRIPTION_MIN = 20
  const DESCRIPTION_MAX = 5000

  // Auto-open widget if ?support=open is in URL
  useEffect(() => {
    if (searchParams.get('support') === 'open') {
      setIsOpen(true)
      // Remove the param from URL to prevent re-opening on refresh
      searchParams.delete('support')
      setSearchParams(searchParams, { replace: true })
    }
  }, [searchParams, setSearchParams])

  useEffect(() => {
    if (isOpen && !context) {
      supportApi.getContext()
        .then(setContext)
        .catch(console.error)
    }
  }, [isOpen, context])

  const validateForm = (): boolean => {
    const newErrors: { subject?: string; description?: string } = {}

    if (subject.length < SUBJECT_MIN) {
      newErrors.subject = `Subject must be at least ${SUBJECT_MIN} characters`
    } else if (subject.length > SUBJECT_MAX) {
      newErrors.subject = `Subject must be no more than ${SUBJECT_MAX} characters`
    }

    if (description.length < DESCRIPTION_MIN) {
      newErrors.description = `Description must be at least ${DESCRIPTION_MIN} characters`
    } else if (description.length > DESCRIPTION_MAX) {
      newErrors.description = `Description must be no more than ${DESCRIPTION_MAX} characters`
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!validateForm()) return

    setIsSubmitting(true)
    setSubmitError(null)  // Clear any previous error
    try {
      const response = await supportApi.submitTicket({
        subject,
        description,
        category,
        cloud_provider: cloudProvider || undefined
      })
      setTicketId(response.ticket_id)
      setMode('success')
      // Reset form
      setSubject('')
      setDescription('')
      setCategory('technical')
      setCloudProvider('')
      setErrors({})
    } catch (error: unknown) {
      console.error('Failed to submit ticket', error)

      // Parse error response for user-friendly message
      let errorMessage = 'Failed to submit ticket. Please try again or email support@a13e.com directly.'

      if (error && typeof error === 'object' && 'response' in error) {
        const axiosError = error as { response?: { status?: number; data?: { detail?: string | Array<{ msg: string; loc: string[] }> } } }
        const response = axiosError.response

        if (response?.status === 422 && response.data?.detail) {
          // Handle Pydantic validation errors
          const detail = response.data.detail
          if (Array.isArray(detail) && detail.length > 0) {
            // Extract field-specific errors with user-friendly formatting
            const fieldErrors = detail.map(err => {
              const field = err.loc[err.loc.length - 1]
              const fieldName = field.charAt(0).toUpperCase() + field.slice(1)
              // Make Pydantic messages more readable
              const msg = err.msg
                .replace('String should have at least', 'must be at least')
                .replace('String should have at most', 'must be no more than')
                .replace('characters', 'characters long')
              return `${fieldName} ${msg}`
            }).join('. ')
            errorMessage = fieldErrors
          } else if (typeof detail === 'string') {
            errorMessage = detail
          }
        } else if (response?.status === 503) {
          errorMessage = 'Service temporarily unavailable. Please try again in a moment.'
        } else if (response?.status === 429) {
          errorMessage = 'Too many requests. Please wait a moment before trying again.'
        }
      }

      setSubmitError(errorMessage)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end space-y-4">
      {/* Widget Content */}
      {isOpen && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-xl w-96 overflow-hidden flex flex-col max-h-[600px] transition-all duration-200 ease-in-out">
          {/* Header */}
          <div className="bg-slate-900 p-4 border-b border-slate-700 flex justify-between items-center">
            <h3 className="text-white font-semibold flex items-center">
              <MessageSquare className="h-5 w-5 mr-2 text-blue-400" />
              A13E Support
            </h3>
            <button
              onClick={() => setIsOpen(false)}
              className="text-slate-400 hover:text-white transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Body */}
          <div className="p-4 flex-1 overflow-y-auto">
            {mode === 'menu' && (
              <div className="space-y-4">
                <div className="text-sm text-slate-300">
                  Hi {user?.full_name?.split(' ')[0] || 'there'}, how can we help you today?
                </div>

                {/* Quick Links (Placeholders for now) */}
                <div className="grid grid-cols-2 gap-3">
                  <a
                    href={USER_DOCS_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="flex flex-col items-center justify-center p-4 bg-slate-700/50 hover:bg-slate-700 rounded-lg border border-slate-600 transition-colors text-center group"
                  >
                    <FileText className="h-6 w-6 text-blue-400 mb-2 group-hover:scale-110 transition-transform" />
                    <span className="text-xs font-medium text-slate-200">Documentation</span>
                  </a>
                  <button
                    onClick={() => setMode('ticket')}
                    className="flex flex-col items-center justify-center p-4 bg-slate-700/50 hover:bg-slate-700 rounded-lg border border-slate-600 transition-colors text-center group"
                  >
                    <MessageSquare className="h-6 w-6 text-green-400 mb-2 group-hover:scale-110 transition-transform" />
                    <span className="text-xs font-medium text-slate-200">Contact Support</span>
                  </button>
                </div>

                {context && (
                  <div className="mt-4 p-3 bg-slate-900/50 rounded border border-slate-800 text-xs text-slate-400">
                    <div className="font-semibold text-slate-300 mb-1">Your Context</div>
                    <div className="grid grid-cols-2 gap-y-1">
                      <span>Tier:</span>
                      <span className="text-right text-slate-200">{context.tier_display}</span>
                      <span>Accounts:</span>
                      <span className="text-right text-slate-200">{context.cloud_accounts_count}</span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {mode === 'ticket' && (
              <form onSubmit={handleSubmit} className="space-y-4">
                <button
                  type="button"
                  onClick={() => setMode('menu')}
                  className="text-xs text-slate-400 hover:text-white mb-2 flex items-center"
                >
                  ← Back to menu
                </button>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Category
                  </label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="technical">Technical Issue</option>
                    <option value="billing">Billing & Subscription</option>
                    <option value="account">Account Access</option>
                    <option value="feature_request">Feature Request</option>
                    <option value="bug_report">Report a Bug</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Subject
                  </label>
                  <input
                    type="text"
                    value={subject}
                    onChange={(e) => {
                      setSubject(e.target.value)
                      if (errors.subject) setErrors(prev => ({ ...prev, subject: undefined }))
                    }}
                    placeholder="Brief summary of the issue"
                    required
                    minLength={SUBJECT_MIN}
                    maxLength={SUBJECT_MAX}
                    className={clsx(
                      "w-full bg-slate-900 border rounded px-3 py-2 text-sm text-white focus:outline-none placeholder-slate-500",
                      errors.subject ? "border-red-500 focus:border-red-500" : "border-slate-700 focus:border-blue-500"
                    )}
                  />
                  {errors.subject && (
                    <p className="mt-1 text-xs text-red-400">{errors.subject}</p>
                  )}
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Description
                    <span className="ml-2 text-slate-500 font-normal">
                      ({description.length}/{DESCRIPTION_MIN} min)
                    </span>
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => {
                      setDescription(e.target.value)
                      if (errors.description) setErrors(prev => ({ ...prev, description: undefined }))
                    }}
                    placeholder="Please describe the issue in detail..."
                    required
                    minLength={DESCRIPTION_MIN}
                    maxLength={DESCRIPTION_MAX}
                    rows={4}
                    className={clsx(
                      "w-full bg-slate-900 border rounded px-3 py-2 text-sm text-white focus:outline-none placeholder-slate-500 resize-none",
                      errors.description ? "border-red-500 focus:border-red-500" : "border-slate-700 focus:border-blue-500"
                    )}
                  />
                  {errors.description && (
                    <p className="mt-1 text-xs text-red-400">{errors.description}</p>
                  )}
                </div>

                {(category === 'technical' || category === 'bug_report') && (
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Cloud Provider (Optional)
                    </label>
                    <div className="flex space-x-2">
                      {['aws', 'gcp', 'multi_cloud'].map((prov) => (
                        <button
                          key={prov}
                          type="button"
                          onClick={() => setCloudProvider(prov === cloudProvider ? '' : prov)}
                          className={clsx(
                            'px-3 py-1.5 rounded text-xs border transition-colors',
                            cloudProvider === prov
                              ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                              : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600'
                          )}
                        >
                          {prov === 'multi_cloud' ? 'Multi' : prov.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {submitError && (
                  <div className="p-3 bg-red-900/50 border border-red-700 rounded-lg text-sm text-red-300 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                    <span>{submitError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-blue-600 hover:bg-blue-500 text-white py-2 rounded font-medium transition-colors flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isSubmitting ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Send className="h-4 w-4 mr-2" />
                  )}
                  Submit Ticket
                </button>
              </form>
            )}

            {mode === 'success' && (
              <div className="flex flex-col items-center justify-center h-full text-center py-8">
                <div className="h-12 w-12 bg-green-500/10 rounded-full flex items-center justify-center mb-4">
                  <Send className="h-6 w-6 text-green-500" />
                </div>
                <h4 className="text-white font-semibold text-lg mb-2">Ticket Submitted!</h4>
                <p className="text-slate-400 text-sm mb-6">
                  Reference: <span className="text-white font-mono">{ticketId}</span>
                  <br />
                  We've sent a confirmation email to {user?.email}. We'll be in touch shortly.
                </p>
                <button
                  onClick={() => {
                    setMode('menu')
                    setIsOpen(false)
                  }}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm transition-colors"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Floating Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={clsx(
          "h-14 w-14 rounded-full shadow-lg flex items-center justify-center transition-all duration-300 hover:scale-105 active:scale-95",
          isOpen ? "bg-slate-700 text-white rotate-90" : "bg-blue-600 hover:bg-blue-500 text-white"
        )}
      >
        {isOpen ? <X className="h-6 w-6" /> : <MessageSquare className="h-6 w-6" />}
      </button>
    </div>
  )
}
