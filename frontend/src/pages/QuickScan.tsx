import { useState } from 'react'
import { Link } from 'react-router'
import {
  ArrowLeft,
  ArrowRight,
  Code2,
  Loader2,
  AlertTriangle,
  Sparkles,
} from 'lucide-react'
import A13ELogo from '../components/A13ELogo'
import QuickScanResults from '../components/QuickScanResults'
import { quickScanApi, type QuickScanResponse } from '../services/quickScanApi'
import { EXAMPLE_TERRAFORM } from '../data/exampleTerraform'

const MAX_CONTENT_LENGTH = 256_000

export default function QuickScan() {
  const [content, setContent] = useState('')
  const [result, setResult] = useState<QuickScanResponse | null>(null)
  const [isAnalysing, setIsAnalysing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleAnalyse = async () => {
    if (!content.trim()) return

    setIsAnalysing(true)
    setError(null)
    setResult(null)

    try {
      const data = await quickScanApi.analyse(content)
      setResult(data)
    } catch (err: unknown) {
      let message = 'Something went wrong. Please check your Terraform and try again.'

      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as {
          response?: { status?: number; data?: { detail?: string } }
        }
        const status = axiosErr.response?.status
        const detail = axiosErr.response?.data?.detail

        if (status === 422) {
          message = detail || 'Invalid Terraform content. Please check the syntax.'
        } else if (status === 408) {
          message = detail || 'Analysis timed out — try a smaller configuration.'
        } else if (status === 429) {
          message = 'Rate limit reached. Please wait a few minutes and try again.'
        }
      }

      setError(message)
    } finally {
      setIsAnalysing(false)
    }
  }

  const handleTryExample = () => {
    setContent(EXAMPLE_TERRAFORM)
    setResult(null)
    setError(null)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 bg-slate-950/95 backdrop-blur-lg border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <Link to="/">
              <A13ELogo size="sm" showTagline={false} />
            </Link>
            <Link
              to="/"
              className="flex items-center gap-2 text-gray-300 hover:text-white transition-colours"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Home
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <div className="pt-24 pb-8 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-full mb-6">
            <Code2 className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-3">Quick Scan</h1>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            Paste your Terraform configuration and get instant MITRE ATT&amp;CK
            coverage analysis — no account required.
          </p>
        </div>
      </div>

      {/* Main content */}
      <div className="pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto space-y-6">
          {/* Input area */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-3">
              <label
                htmlFor="terraform-input"
                className="text-sm font-medium text-gray-300"
              >
                Terraform HCL Configuration
              </label>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500">
                  {content.length.toLocaleString()} / {MAX_CONTENT_LENGTH.toLocaleString()}
                </span>
                <button
                  type="button"
                  onClick={handleTryExample}
                  className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colours"
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  Try Example
                </button>
              </div>
            </div>

            <textarea
              id="terraform-input"
              value={content}
              onChange={(e) => {
                setContent(e.target.value)
                if (error) setError(null)
              }}
              placeholder={`resource "aws_guardduty_detector" "main" {\n  enable = true\n}`}
              rows={14}
              maxLength={MAX_CONTENT_LENGTH}
              spellCheck={false}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-sm text-gray-100 font-mono focus:outline-none focus:border-blue-500 placeholder-slate-600 resize-y"
            />

            {/* Error message */}
            {error && (
              <div className="mt-3 p-3 bg-red-900/40 border border-red-700 rounded-lg text-sm text-red-300 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            {/* Analyse button */}
            <button
              type="button"
              onClick={handleAnalyse}
              disabled={isAnalysing || !content.trim()}
              className="mt-4 w-full sm:w-auto bg-blue-600 hover:bg-blue-500 text-white px-6 py-2.5 rounded-lg font-medium transition-colours flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isAnalysing ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Analysing…
                </>
              ) : (
                'Analyse Configuration'
              )}
            </button>
          </div>

          {/* Results */}
          {result && <QuickScanResults data={result} />}

          {/* CTA */}
          {result && (
            <div className="bg-gradient-to-r from-blue-900/40 to-cyan-900/40 border border-blue-700/50 rounded-lg p-6 text-center">
              <h3 className="text-lg font-semibold text-white mb-2">
                Want continuous coverage monitoring?
              </h3>
              <p className="text-gray-400 text-sm mb-4 max-w-lg mx-auto">
                Connect your AWS, GCP, or Azure accounts for live detection
                scanning, compliance mapping, and remediation guidance.
              </p>
              <Link
                to="/signup"
                className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-6 py-2.5 rounded-lg font-medium transition-colours"
              >
                Create Free Account
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-sm text-gray-500">
            &copy; {new Date().getFullYear()} A13E. All rights reserved.
          </p>
          <div className="flex items-center gap-6 text-sm text-gray-500">
            <Link to="/terms" className="hover:text-gray-300 transition-colours">
              Terms
            </Link>
            <Link to="/privacy" className="hover:text-gray-300 transition-colours">
              Privacy
            </Link>
            <Link to="/security" className="hover:text-gray-300 transition-colours">
              Security
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
