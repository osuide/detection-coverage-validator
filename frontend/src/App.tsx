import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import Dashboard from './pages/Dashboard'
import Accounts from './pages/Accounts'
import Detections from './pages/Detections'
import Coverage from './pages/Coverage'
import Gaps from './pages/Gaps'
import Login from './pages/Login'
import Signup from './pages/Signup'
import TeamManagement from './pages/TeamManagement'
import APIKeys from './pages/APIKeys'
import AuditLogs from './pages/AuditLogs'
import Profile from './pages/Profile'
import AuthCallback from './pages/AuthCallback'
import OrgSecurity from './pages/OrgSecurity'
import Billing from './pages/Billing'
import Landing from './pages/Landing'

// Documentation pages
import { DocsIndex } from './pages/docs/DocsIndex'
import { DocsPage } from './pages/docs/DocsPage'

// Admin Portal pages
import AdminLogin from './pages/admin/AdminLogin'
import AdminDashboard from './pages/admin/AdminDashboard'
import AdminSettings from './pages/admin/AdminSettings'
import AdminOrganizations from './pages/admin/AdminOrganizations'
import AdminUsers from './pages/admin/AdminUsers'
import AdminAuditLogs from './pages/admin/AdminAuditLogs'
import AdminBilling from './pages/admin/AdminBilling'
import AdminAdmins from './pages/admin/AdminAdmins'

function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/auth/callback" element={<AuthCallback />} />

        {/* Documentation routes (public) */}
        <Route path="/docs" element={<DocsIndex />} />
        <Route path="/docs/:slug" element={<DocsPage />} />

        {/* Admin Portal routes (separate auth) */}
        <Route path="/admin/login" element={<AdminLogin />} />
        <Route path="/admin/dashboard" element={<AdminDashboard />} />
        <Route path="/admin/settings" element={<AdminSettings />} />
        <Route path="/admin/organizations" element={<AdminOrganizations />} />
        <Route path="/admin/users" element={<AdminUsers />} />
        <Route path="/admin/audit-logs" element={<AdminAuditLogs />} />
        <Route path="/admin/billing" element={<AdminBilling />} />
        <Route path="/admin/admins" element={<AdminAdmins />} />

        {/* Protected routes */}
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/accounts" element={<Accounts />} />
                  <Route path="/detections" element={<Detections />} />
                  <Route path="/coverage" element={<Coverage />} />
                  <Route path="/gaps" element={<Gaps />} />
                  <Route path="/settings" element={<Navigate to="/settings/profile" replace />} />
                  <Route path="/settings/team" element={<TeamManagement />} />
                  <Route path="/settings/api-keys" element={<APIKeys />} />
                  <Route path="/settings/audit-logs" element={<AuditLogs />} />
                  <Route path="/settings/profile" element={<Profile />} />
                  <Route path="/settings/security" element={<OrgSecurity />} />
                  <Route path="/settings/billing" element={<Billing />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </AuthProvider>
  )
}

export default App
