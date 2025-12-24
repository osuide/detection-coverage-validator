import { Link } from 'react-router-dom';
import {
  BookOpen,
  Cloud,
  Play,
  BarChart3,
  Users,
  CreditCard,
  ArrowRight,
  Zap,
  Clock,
} from 'lucide-react';
import { DocsLayout } from '../../components/docs/DocsLayout';
import { docPages } from './docs-content';

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  BookOpen,
  Cloud,
  Play,
  BarChart3,
  Users,
  CreditCard,
};

export function DocsIndex() {
  return (
    <DocsLayout>
      {/* Hero */}
      <div className="relative overflow-hidden mb-16">
        {/* Gradient background */}
        <div className="absolute inset-0 -z-10">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyan-600/10 rounded-full blur-3xl" />
        </div>

        <div className="text-center py-12">
          <div className="inline-flex items-center gap-2 bg-blue-600/10 border border-blue-500/20 rounded-full px-4 py-2 mb-6">
            <BookOpen className="h-4 w-4 text-blue-400" />
            <span className="text-sm text-blue-300 font-medium">Documentation</span>
          </div>

          <h1 className="text-5xl font-bold text-white mb-6">
            A13E Documentation
          </h1>
          <p className="text-xl text-white max-w-2xl mx-auto leading-relaxed">
            Everything you need to get started with the A13E Detection Coverage Validator.
            Analyse your cloud security posture using the MITRE ATT&CK framework.
          </p>
        </div>
      </div>

      {/* Quick Start */}
      <div className="bg-gradient-to-r from-blue-600 to-cyan-600 rounded-2xl p-8 mb-12 relative overflow-hidden shadow-2xl shadow-blue-500/25">
        <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/20" />
        <div className="relative z-10">
          <h2 className="text-2xl font-bold mb-6 text-white flex items-center gap-3">
            <Zap className="h-6 w-6" />
            Quick Start
          </h2>
          <ol className="space-y-4 text-blue-100 mb-8">
            <li className="flex items-start gap-4">
              <span className="flex-shrink-0 w-8 h-8 bg-white/20 rounded-full flex items-center justify-center text-sm font-bold">
                1
              </span>
              <div>
                <span className="font-semibold text-white">Create your account</span>
                <span className="text-blue-200"> — Sign up with email or SSO (Google/GitHub)</span>
              </div>
            </li>
            <li className="flex items-start gap-4">
              <span className="flex-shrink-0 w-8 h-8 bg-white/20 rounded-full flex items-center justify-center text-sm font-bold">
                2
              </span>
              <div>
                <span className="font-semibold text-white">Connect your AWS account</span>
                <span className="text-blue-200"> — Use CloudFormation for quick setup (5 min)</span>
              </div>
            </li>
            <li className="flex items-start gap-4">
              <span className="flex-shrink-0 w-8 h-8 bg-white/20 rounded-full flex items-center justify-center text-sm font-bold">
                3
              </span>
              <div>
                <span className="font-semibold text-white">Run your first scan</span>
                <span className="text-blue-200"> — Explore coverage results and gap analysis</span>
              </div>
            </li>
          </ol>
          <Link
            to="/docs/getting-started"
            className="inline-flex items-center gap-2 bg-white text-blue-600 font-semibold px-6 py-3 rounded-xl hover:bg-blue-50 transition-colors shadow-lg"
          >
            Get Started
            <ArrowRight className="h-5 w-5" />
          </Link>
        </div>
      </div>

      {/* Doc Cards Grid */}
      <div className="grid md:grid-cols-2 gap-6">
        {docPages.map((doc) => {
          const Icon = iconMap[doc.icon] || BookOpen;
          return (
            <Link
              key={doc.slug}
              to={`/docs/${doc.slug}`}
              className="group p-6 bg-slate-900/50 border border-slate-800 rounded-xl hover:border-blue-500/50 hover:bg-slate-800/50 hover:shadow-xl hover:shadow-blue-500/10 transition-all"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-xl group-hover:scale-110 transition-transform shadow-lg shadow-blue-500/25">
                  <Icon className="h-6 w-6 text-white" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="font-semibold text-white group-hover:text-blue-400 mb-2 transition-colors">
                    {doc.title}
                  </h3>
                  <p className="text-sm text-gray-400 mb-3 line-clamp-2">{doc.description}</p>
                  <span className="text-xs text-gray-400 flex items-center gap-1.5">
                    <Clock className="h-3 w-3" />
                    {doc.readTime} read
                  </span>
                </div>
                <ArrowRight className="h-5 w-5 text-gray-400 group-hover:text-blue-400 group-hover:translate-x-1 transition-all flex-shrink-0 mt-1" />
              </div>
            </Link>
          );
        })}
      </div>

      {/* Support */}
      <div className="mt-16 p-8 bg-gray-700/30 border border-gray-700 rounded-2xl text-center">
        <h3 className="font-semibold text-white text-lg mb-2">Need help?</h3>
        <p className="text-gray-400 mb-6">
          Can't find what you're looking for? Our support team is here to help.
        </p>
        <a
          href="mailto:support@a13e.com"
          className="inline-flex items-center gap-2 text-blue-400 font-medium hover:text-blue-300 transition-colors"
        >
          Contact Support
          <ArrowRight className="h-4 w-4" />
        </a>
      </div>
    </DocsLayout>
  );
}
