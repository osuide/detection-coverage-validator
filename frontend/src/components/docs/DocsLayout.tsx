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
} from 'lucide-react';
import { useState } from 'react';
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

interface DocsLayoutProps {
  children: React.ReactNode;
}

export function DocsLayout({ children }: DocsLayoutProps) {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const currentSlug = location.pathname.replace('/docs/', '').replace('/docs', '');

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-4">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden p-2 text-gray-500 hover:text-gray-700"
              >
                {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
              </button>
              <Link to="/" className="flex items-center gap-2">
                <A13ELogo size="sm" />
              </Link>
              <span className="hidden sm:inline text-gray-300">|</span>
              <Link to="/docs" className="hidden sm:inline text-sm font-medium text-gray-600 hover:text-gray-900">
                Documentation
              </Link>
            </div>
            <div className="flex items-center gap-4">
              <Link
                to="/login"
                className="text-sm font-medium text-gray-600 hover:text-gray-900"
              >
                Sign in
              </Link>
              <Link
                to="/signup"
                className="text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg"
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
            fixed lg:sticky top-16 left-0 z-40 w-64 h-[calc(100vh-4rem)] bg-gray-50 border-r border-gray-200
            transform transition-transform duration-200 ease-in-out overflow-y-auto
            ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          `}
        >
          <nav className="p-4">
            <div className="mb-6">
              <Link
                to="/"
                className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700"
              >
                <ArrowLeft className="h-4 w-4" />
                Back to A13E
              </Link>
            </div>

            <div className="mb-2 px-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">
              Documentation
            </div>

            <ul className="space-y-1">
              {docPages.map((doc) => {
                const Icon = iconMap[doc.icon] || BookOpen;
                const isActive = currentSlug === doc.slug;
                return (
                  <li key={doc.slug}>
                    <Link
                      to={`/docs/${doc.slug}`}
                      onClick={() => setSidebarOpen(false)}
                      className={`
                        flex items-center gap-3 px-3 py-2 rounded-lg text-sm
                        ${isActive
                          ? 'bg-blue-50 text-blue-700 font-medium'
                          : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
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

            <div className="mt-8 pt-6 border-t border-gray-200">
              <div className="px-3 text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Need Help?
              </div>
              <a
                href="mailto:support@a13e.io"
                className="block px-3 py-2 text-sm text-gray-600 hover:text-gray-900"
              >
                Contact Support
              </a>
            </div>
          </nav>
        </aside>

        {/* Mobile overlay */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-30 bg-black/20 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Main content */}
        <main className="flex-1 min-w-0">
          <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
