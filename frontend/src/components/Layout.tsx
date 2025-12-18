import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Cloud,
  Shield,
  BarChart3,
  AlertTriangle,
  Settings
} from 'lucide-react'
import { clsx } from 'clsx'

interface LayoutProps {
  children: ReactNode
}

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Accounts', href: '/accounts', icon: Cloud },
  { name: 'Detections', href: '/detections', icon: Shield },
  { name: 'Coverage', href: '/coverage', icon: BarChart3 },
  { name: 'Gaps', href: '/gaps', icon: AlertTriangle },
]

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-64 bg-slate-900">
        <div className="flex h-16 items-center justify-center border-b border-slate-800">
          <Shield className="h-8 w-8 text-blue-400" />
          <span className="ml-2 text-lg font-semibold text-white">DCV</span>
        </div>
        <nav className="mt-6 px-3">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                className={clsx(
                  'flex items-center px-3 py-2 mt-1 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                )}
              >
                <item.icon className="h-5 w-5 mr-3" />
                {item.name}
              </Link>
            )
          })}
        </nav>
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-slate-800">
          <Link
            to="/settings"
            className="flex items-center px-3 py-2 rounded-lg text-sm font-medium text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <Settings className="h-5 w-5 mr-3" />
            Settings
          </Link>
        </div>
      </div>

      {/* Main content */}
      <div className="pl-64">
        <main className="p-8">
          {children}
        </main>
      </div>
    </div>
  )
}
