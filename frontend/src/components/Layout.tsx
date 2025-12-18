import { ReactNode, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Cloud,
  Shield,
  BarChart3,
  AlertTriangle,
  Settings,
  LogOut,
  User,
  Building,
  ChevronDown,
  Users,
  Key,
  FileText,
  Lock,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '../contexts/AuthContext'

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
  const navigate = useNavigate()
  const { user, organization, logout } = useAuth()
  const [showUserMenu, setShowUserMenu] = useState(false)

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-64 bg-slate-900">
        <div className="flex h-16 items-center justify-center border-b border-slate-800">
          <Shield className="h-8 w-8 text-blue-400" />
          <span className="ml-2 text-lg font-semibold text-white">DCV</span>
        </div>

        {/* Organization info */}
        {organization && (
          <div className="px-3 py-3 border-b border-slate-800">
            <div className="flex items-center px-3 py-2 text-slate-300">
              <Building className="h-4 w-4 mr-2" />
              <span className="text-sm font-medium truncate">{organization.name}</span>
            </div>
          </div>
        )}

        <nav className="mt-4 px-3">
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

        {/* User section at bottom */}
        <div className="absolute bottom-0 left-0 right-0 border-t border-slate-800">
          <Link
            to="/settings/team"
            className={clsx(
              'flex items-center px-6 py-3 text-sm font-medium transition-colors',
              location.pathname === '/settings/team'
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            )}
          >
            <Users className="h-5 w-5 mr-3" />
            Team
          </Link>
          <Link
            to="/settings/api-keys"
            className={clsx(
              'flex items-center px-6 py-3 text-sm font-medium transition-colors',
              location.pathname === '/settings/api-keys'
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            )}
          >
            <Key className="h-5 w-5 mr-3" />
            API Keys
          </Link>
          <Link
            to="/settings/audit-logs"
            className={clsx(
              'flex items-center px-6 py-3 text-sm font-medium transition-colors',
              location.pathname === '/settings/audit-logs'
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            )}
          >
            <FileText className="h-5 w-5 mr-3" />
            Audit Logs
          </Link>
          <Link
            to="/settings/security"
            className={clsx(
              'flex items-center px-6 py-3 text-sm font-medium transition-colors',
              location.pathname === '/settings/security'
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            )}
          >
            <Lock className="h-5 w-5 mr-3" />
            Security
          </Link>
          <Link
            to="/settings"
            className="flex items-center px-6 py-3 text-sm font-medium text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <Settings className="h-5 w-5 mr-3" />
            Settings
          </Link>

          {/* User dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="w-full flex items-center px-6 py-3 text-sm text-slate-300 hover:bg-slate-800 transition-colors"
            >
              <div className="h-8 w-8 rounded-full bg-slate-700 flex items-center justify-center mr-3">
                <User className="h-4 w-4" />
              </div>
              <div className="flex-1 text-left">
                <div className="font-medium truncate">{user?.full_name}</div>
                <div className="text-xs text-slate-500 truncate">{user?.email}</div>
              </div>
              <ChevronDown className={clsx(
                'h-4 w-4 transition-transform',
                showUserMenu && 'rotate-180'
              )} />
            </button>

            {showUserMenu && (
              <div className="absolute bottom-full left-0 right-0 mb-1 mx-3 bg-slate-800 rounded-lg shadow-lg border border-slate-700 overflow-hidden">
                <Link
                  to="/settings/profile"
                  className="flex items-center px-4 py-2 text-sm text-slate-300 hover:bg-slate-700"
                  onClick={() => setShowUserMenu(false)}
                >
                  <User className="h-4 w-4 mr-2" />
                  Profile
                </Link>
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center px-4 py-2 text-sm text-red-400 hover:bg-slate-700"
                >
                  <LogOut className="h-4 w-4 mr-2" />
                  Sign out
                </button>
              </div>
            )}
          </div>
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
