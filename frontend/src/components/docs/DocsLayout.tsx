import { Link, useLocation } from 'react-router-dom';
import {
  BookOpen,
  Cloud,
  Play,
  BarChart3,
  Users,
  CreditCard,
  ArrowLeft,
  Menu,
  X,
  Mail,
  ExternalLink,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import { docPages } from '../../pages/docs/docs-content';
import A13ELogo from '../A13ELogo';

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  BookOpen,
  Cloud,
  Play,
  BarChart3,
  Users,
  CreditCard,
};

// Group docs into sections
const docSections = [
  {
    title: 'Getting Started',
    pages: docPages.filter(d => ['getting-started', 'connecting-aws'].includes(d.slug)),
  },
  {
    title: 'Features',
    pages: docPages.filter(d => ['running-scans', 'understanding-coverage'].includes(d.slug)),
  },
  {
    title: 'Management',
    pages: docPages.filter(d => ['team-management', 'billing'].includes(d.slug)),
  },
];

interface DocsLayoutProps {
  children: React.ReactNode;
}

export function DocsLayout({ children }: DocsLayoutProps) {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const currentSlug = location.pathname.replace('/docs/', '').replace('/docs', '');

  // Lock scroll when mobile sidebar is open
  useEffect(() => {
    if (sidebarOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [sidebarOpen]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-slate-950/95 backdrop-blur-lg border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-6">
              {/* Mobile menu button */}
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden p-2 text-gray-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
              >
                {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
              </button>

              {/* Logo */}
              <Link to="/" className="flex items-center gap-2">
                <A13ELogo size="sm" />
              </Link>

              {/* Separator */}
              <div className="hidden sm:block h-6 w-px bg-slate-700" />

              {/* Navigation tabs */}
              <nav className="hidden md:flex items-center gap-1">
                <Link
                  to="/docs"
                  className="px-3 py-1.5 text-sm font-medium text-blue-400 bg-blue-400/10 rounded-lg"
                >
                  Documentation
                </Link>
              </nav>
            </div>

            {/* Right side */}
            <div className="flex items-center gap-4">
              <Link
                to="/login"
                className="hidden sm:inline-block text-sm font-medium text-gray-400 hover:text-white transition-colors"
              >
                Sign in
              </Link>
              <Link
                to="/signup"
                className="text-sm font-medium text-white bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 px-4 py-2 rounded-lg shadow-lg shadow-blue-500/25 transition-all"
              >
                Get Started
              </Link>
            </div>
          </div>
        </div>
      </header>

      <div className="flex pt-16">
        {/* Sidebar */}
        <aside
          className={`
            fixed lg:sticky top-16 left-0 z-40 w-72 h-[calc(100vh-4rem)] bg-slate-900/95 backdrop-blur-lg border-r border-slate-800
            transform transition-transform duration-200 ease-in-out overflow-y-auto
            ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          `}
        >
          <nav className="p-6 space-y-8">
            {/* Back link */}
            <div>
              <Link
                to="/"
                className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors group"
              >
                <ArrowLeft className="h-4 w-4 group-hover:-translate-x-1 transition-transform" />
                Back to A13E
              </Link>
            </div>

            {/* Doc sections */}
            {docSections.map((section) => (
              <div key={section.title}>
                <div className="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                  {section.title}
                </div>
                <ul className="space-y-1">
                  {section.pages.map((doc) => {
                    const Icon = iconMap[doc.icon] || BookOpen;
                    const isActive = currentSlug === doc.slug;
                    return (
                      <li key={doc.slug}>
                        <Link
                          to={`/docs/${doc.slug}`}
                          onClick={() => setSidebarOpen(false)}
                          className={`
                            flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all
                            ${isActive
                              ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-semibold shadow-lg shadow-blue-500/25'
                              : 'text-gray-400 hover:bg-slate-800 hover:text-white'
                            }
                          `}
                        >
                          <Icon className="h-4 w-4 flex-shrink-0" />
                          <span>{doc.title}</span>
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}

            {/* Additional Links */}
            <div className="pt-6 border-t border-slate-800">
              <div className="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
                Resources
              </div>
              <ul className="space-y-1">
                <li>
                  <a
                    href="mailto:support@a13e.io"
                    className="flex items-center gap-3 px-3 py-2.5 text-sm text-gray-400 hover:bg-slate-800 hover:text-white rounded-lg transition-colors"
                  >
                    <Mail className="h-4 w-4" />
                    Contact Support
                  </a>
                </li>
                <li>
                  <a
                    href="https://attack.mitre.org/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-3 px-3 py-2.5 text-sm text-gray-400 hover:bg-slate-800 hover:text-white rounded-lg transition-colors"
                  >
                    <ExternalLink className="h-4 w-4" />
                    MITRE ATT&CK
                  </a>
                </li>
              </ul>
            </div>
          </nav>
        </aside>

        {/* Mobile overlay */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Main content */}
        <main className="flex-1 min-w-0">
          <div className="max-w-5xl px-8 sm:px-12 lg:px-16 py-12">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
