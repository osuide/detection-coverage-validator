import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router'
import {
  MessageSquare,
  X,
  Send,
  Loader2,
  FileText
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!subject || !description) return

    setIsSubmitting(true)
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
    } catch (error) {
      console.error('Failed to submit ticket', error)
      // Ideally show error toast here
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
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="Brief summary of the issue"
                    required
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 placeholder-slate-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Description
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Please describe the issue in detail..."
                    required
                    rows={4}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 placeholder-slate-500 resize-none"
                  />
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
