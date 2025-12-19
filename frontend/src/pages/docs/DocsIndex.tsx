import { Link } from 'react-router-dom';
import {
  BookOpen,
  Cloud,
  Play,
  BarChart3,
  Users,
  CreditCard,
  ArrowRight,
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
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">
          A13E Documentation
        </h1>
        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
          Everything you need to get started with the A13E Detection Coverage Validator.
          Analyze your cloud security posture using the MITRE ATT&CK framework.
        </p>
      </div>

      {/* Quick Start */}
      <div className="bg-gradient-to-r from-blue-600 to-cyan-600 rounded-2xl p-8 mb-12 text-white">
        <h2 className="text-2xl font-bold mb-4">Quick Start</h2>
        <ol className="space-y-3 text-blue-100 mb-6">
          <li className="flex items-start gap-3">
            <span className="flex-shrink-0 w-6 h-6 bg-white/20 rounded-full flex items-center justify-center text-sm font-medium">1</span>
            <span>Create your account with email or SSO (Google/GitHub)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="flex-shrink-0 w-6 h-6 bg-white/20 rounded-full flex items-center justify-center text-sm font-medium">2</span>
            <span>Connect your AWS account using CloudFormation (5 min)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="flex-shrink-0 w-6 h-6 bg-white/20 rounded-full flex items-center justify-center text-sm font-medium">3</span>
            <span>Run your first scan and explore coverage results</span>
          </li>
        </ol>
        <Link
          to="/docs/getting-started"
          className="inline-flex items-center gap-2 bg-white text-blue-600 font-medium px-6 py-3 rounded-lg hover:bg-blue-50 transition-colors"
        >
          Get Started
          <ArrowRight className="h-4 w-4" />
        </Link>
      </div>

      {/* Doc Cards Grid */}
      <div className="grid md:grid-cols-2 gap-6">
        {docPages.map((doc) => {
          const Icon = iconMap[doc.icon] || BookOpen;
          return (
            <Link
              key={doc.slug}
              to={`/docs/${doc.slug}`}
              className="group p-6 bg-white border border-gray-200 rounded-xl hover:border-blue-300 hover:shadow-md transition-all"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-gray-100 rounded-lg group-hover:bg-blue-50 transition-colors">
                  <Icon className="h-6 w-6 text-gray-600 group-hover:text-blue-600" />
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold text-gray-900 group-hover:text-blue-600 mb-1">
                    {doc.title}
                  </h3>
                  <p className="text-sm text-gray-600 mb-2">{doc.description}</p>
                  <span className="text-xs text-gray-400">{doc.readTime} read</span>
                </div>
                <ArrowRight className="h-5 w-5 text-gray-300 group-hover:text-blue-500 transition-colors" />
              </div>
            </Link>
          );
        })}
      </div>

      {/* Support */}
      <div className="mt-12 p-6 bg-gray-50 rounded-xl text-center">
        <h3 className="font-semibold text-gray-900 mb-2">Need help?</h3>
        <p className="text-gray-600 mb-4">
          Can't find what you're looking for? Our support team is here to help.
        </p>
        <a
          href="mailto:support@a13e.io"
          className="inline-flex items-center gap-2 text-blue-600 font-medium hover:text-blue-700"
        >
          Contact Support
          <ArrowRight className="h-4 w-4" />
        </a>
      </div>
    </DocsLayout>
  );
}
