import { ReactNode, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Cloud,
  BarChart3,
  AlertTriangle,
  Settings,
  LogOut,
  User,
  Building,
  Building2,
  ChevronDown,
  ChevronRight,
  Users,
  Key,
  FileText,
  Lock,
  CreditCard,
  Shield,
  ClipboardCheck,
  FileBarChart,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '../contexts/AuthContext'
import A13ELogo from './A13ELogo'
import AccountSelector from './AccountSelector'

interface LayoutProps {
  children: ReactNode
}

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Organisations', href: '/organizations', icon: Building2 },
  { name: 'Accounts', href: '/accounts', icon: Cloud },
  { name: 'Detections', href: '/detections', icon: Shield },
  { name: 'Coverage', href: '/coverage', icon: BarChart3 },
  { name: 'Compliance', href: '/compliance', icon: ClipboardCheck },
  { name: 'Gaps', href: '/gaps', icon: AlertTriangle },
  { name: 'Reports', href: '/reports', icon: FileBarChart },
]

const settingsNavigation = [
  { name: 'Team', href: '/settings/team', icon: Users },
  { name: 'Security', href: '/settings/security', icon: Lock },
  { name: 'Billing', href: '/settings/billing', icon: CreditCard },
  { name: 'API Keys', href: '/settings/api-keys', icon: Key },
  { name: 'Audit Logs', href: '/settings/audit-logs', icon: FileText },
]

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, organization, logout } = useAuth()
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [showSettingsMenu, setShowSettingsMenu] = useState(
    location.pathname.startsWith('/settings')
  )

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const isSettingsActive = location.pathname.startsWith('/settings')

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Sidebar */}
      <div className="fixed inset-y-0 left-0 w-64 bg-slate-900 flex flex-col">
        <div className="flex h-16 items-center justify-center border-b border-slate-800">
          <A13ELogo size="sm" showTagline={false} />
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

        {/* Cloud Account Selector */}
        <div className="px-3 py-3 border-b border-slate-800">
          <AccountSelector />
        </div>

        {/* Main navigation */}
        <nav className="mt-4 px-3 flex-1">
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

          {/* Settings dropdown */}
          <div className="mt-4">
            <button
              onClick={() => setShowSettingsMenu(!showSettingsMenu)}
              className={clsx(
                'w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                isSettingsActive
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-white'
              )}
            >
              <div className="flex items-center">
                <Settings className="h-5 w-5 mr-3" />
                Settings
              </div>
              {showSettingsMenu ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
            </button>

            {showSettingsMenu && (
              <div className="mt-1 ml-4 space-y-1">
                {settingsNavigation.map((item) => {
                  const isActive = location.pathname === item.href
                  return (
                    <Link
                      key={item.name}
                      to={item.href}
                      className={clsx(
                        'flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-slate-700 text-white'
                          : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                      )}
                    >
                      <item.icon className="h-4 w-4 mr-3" />
                      {item.name}
                    </Link>
                  )
                })}
              </div>
            )}
          </div>
        </nav>

        {/* User section at bottom */}
        <div className="border-t border-slate-800">
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
