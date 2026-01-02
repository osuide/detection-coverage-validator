import { Link } from 'react-router'
import { ArrowLeft, MessageSquare, FileText, Headphones } from 'lucide-react'
import A13ELogo from '../components/A13ELogo'

export default function Support() {
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
              className="flex items-center gap-2 text-gray-300 hover:text-white transition-colors"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Home
            </Link>
          </div>
        </div>
      </nav>

      {/* Content */}
      <div className="pt-24 pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl font-bold text-white mb-4">Support</h1>
          <p className="text-gray-400 text-lg mb-12">
            Get help with A13E Detection Coverage Validator.
          </p>

          <div className="grid md:grid-cols-3 gap-6">
            {/* In-App Support */}
            <div className="p-6 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
              <div className="w-12 h-12 bg-blue-500/10 rounded-lg flex items-center justify-center mb-4">
                <Headphones className="h-6 w-6 text-blue-400" />
              </div>
              <h2 className="text-xl font-semibold text-white mb-2">Contact Support</h2>
              <p className="text-gray-400 mb-4">
                Get help directly from our support team via the in-app widget.
              </p>
              <Link
                to="/dashboard?support=open"
                className="text-blue-400 hover:text-blue-300 font-medium"
              >
                Open Support Widget →
              </Link>
            </div>

            {/* Documentation */}
            <div className="p-6 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
              <div className="w-12 h-12 bg-emerald-500/10 rounded-lg flex items-center justify-center mb-4">
                <FileText className="h-6 w-6 text-emerald-400" />
              </div>
              <h2 className="text-xl font-semibold text-white mb-2">Documentation</h2>
              <p className="text-gray-400 mb-4">
                Browse our guides and documentation.
              </p>
              <Link
                to="/docs"
                className="text-emerald-400 hover:text-emerald-300 font-medium"
              >
                View Docs
              </Link>
            </div>

            {/* Feature Requests */}
            <div className="p-6 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
              <div className="w-12 h-12 bg-purple-500/10 rounded-lg flex items-center justify-center mb-4">
                <MessageSquare className="h-6 w-6 text-purple-400" />
              </div>
              <h2 className="text-xl font-semibold text-white mb-2">Feedback</h2>
              <p className="text-gray-400 mb-4">
                Share ideas or report issues.
              </p>
              <a
                href="mailto:feedback@a13e.com"
                className="text-purple-400 hover:text-purple-300 font-medium"
              >
                feedback@a13e.com
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-8 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
            <p className="text-gray-500 text-sm">
              &copy; {new Date().getFullYear()} A13E. All rights reserved. An OSUIDE INC Company.
            </p>
            <div className="flex gap-6">
              <Link to="/terms" className="text-gray-400 hover:text-white text-sm transition-colors">
                Terms
              </Link>
              <Link to="/privacy" className="text-gray-400 hover:text-white text-sm transition-colors">
                Privacy
              </Link>
              <Link to="/security" className="text-gray-400 hover:text-white text-sm transition-colors">
                Security
              </Link>
              <Link to="/compliance-info" className="text-gray-400 hover:text-white text-sm transition-colors">
                Compliance
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
