import { Routes, Route, Navigate } from 'react-router'
import { Toaster } from 'react-hot-toast'
import { AuthProvider } from './contexts/AuthContext'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import Dashboard from './pages/Dashboard'
import Accounts from './pages/Accounts'
import Detections from './pages/Detections'
import Coverage from './pages/Coverage'
import Compliance from './pages/Compliance'
import Gaps from './pages/Gaps'
import TechniqueDetail from './pages/TechniqueDetail'
import Reports from './pages/Reports'
import Login from './pages/Login'
import Signup from './pages/Signup'
import TeamManagement from './pages/TeamManagement'
import APIKeys from './pages/APIKeys'
import AuditLogs from './pages/AuditLogs'
import Profile from './pages/Profile'
import AuthCallback from './pages/AuthCallback'
import OrgSecurity from './pages/OrgSecurity'
import Billing from './pages/Billing'
import AcknowledgedGapsReview from './pages/AcknowledgedGapsReview'
import ComplianceHistory from './pages/ComplianceHistory'
import Landing from './pages/Landing'
import Terms from './pages/Terms'
import Privacy from './pages/Privacy'
import Security from './pages/Security'
import ComplianceInfo from './pages/ComplianceInfo'
import Support from './pages/Support'

// Organisation pages
import Organizations from './pages/Organizations'
import ConnectOrganization from './pages/ConnectOrganization'
import OrganizationDashboard from './pages/OrganizationDashboard'
import OrganizationMembers from './pages/OrganizationMembers'

// Documentation pages
import { DocsIndex } from './pages/docs/DocsIndex'
import { DocsPage } from './pages/docs/DocsPage'

// Admin Portal pages
import AdminLogin from './pages/admin/AdminLogin'
import AdminDashboard from './pages/admin/AdminDashboard'
import AdminSettings from './pages/admin/AdminSettings'
import AdminOrganizations from './pages/admin/AdminOrganizations'
import AdminUsers from './pages/admin/AdminUsers'
import AdminFingerprints from './pages/admin/AdminFingerprints'
import AdminAuditLogs from './pages/admin/AdminAuditLogs'
import AdminBilling from './pages/admin/AdminBilling'
import AdminAdmins from './pages/admin/AdminAdmins'
import AdminMitreData from './pages/admin/AdminMitreData'
import AdminProfile from './pages/admin/AdminProfile'
import AdminAuthProvider from './components/AdminAuthProvider'

function App() {
  return (
    <AuthProvider>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#1f2937',
            color: '#f9fafb',
          },
          success: {
            iconTheme: {
              primary: '#10b981',
              secondary: '#f9fafb',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#f9fafb',
            },
          },
        }}
      />
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/auth/callback" element={<AuthCallback />} />
        <Route path="/terms" element={<Terms />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/security" element={<Security />} />
        <Route path="/compliance-info" element={<ComplianceInfo />} />
        <Route path="/support" element={<Support />} />

        {/* Documentation routes (public) */}
        <Route path="/docs" element={<DocsIndex />} />
        <Route path="/docs/:slug" element={<DocsPage />} />

        {/* Admin Portal routes (separate auth with session restoration) */}
        <Route path="/admin/*" element={
          <AdminAuthProvider>
            <Routes>
              <Route path="login" element={<AdminLogin />} />
              <Route path="dashboard" element={<AdminDashboard />} />
              <Route path="settings" element={<AdminSettings />} />
              <Route path="organizations" element={<AdminOrganizations />} />
              <Route path="users" element={<AdminUsers />} />
              <Route path="fingerprints" element={<AdminFingerprints />} />
              <Route path="audit-logs" element={<AdminAuditLogs />} />
              <Route path="billing" element={<AdminBilling />} />
              <Route path="admins" element={<AdminAdmins />} />
              <Route path="mitre" element={<AdminMitreData />} />
              <Route path="profile" element={<AdminProfile />} />
            </Routes>
          </AdminAuthProvider>
        } />

        {/* Protected routes */}
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/organizations" element={<Organizations />} />
                  <Route path="/organizations/connect" element={<ConnectOrganization />} />
                  <Route path="/organizations/:orgId" element={<OrganizationDashboard />} />
                  <Route path="/organizations/:orgId/members" element={<OrganizationMembers />} />
                  <Route path="/accounts" element={<Accounts />} />
                  <Route path="/detections" element={<Detections />} />
                  <Route path="/coverage" element={<Coverage />} />
                  <Route path="/compliance" element={<Compliance />} />
                  <Route path="/compliance/history" element={<ComplianceHistory />} />
                  <Route path="/gaps" element={<Gaps />} />
                  <Route path="/techniques/:techniqueId" element={<TechniqueDetail />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/settings" element={<Navigate to="/settings/profile" replace />} />
                  <Route path="/settings/team" element={<TeamManagement />} />
                  <Route path="/settings/api-keys" element={<APIKeys />} />
                  <Route path="/settings/audit-logs" element={<AuditLogs />} />
                  <Route path="/settings/profile" element={<Profile />} />
                  <Route path="/settings/security" element={<OrgSecurity />} />
                  <Route path="/settings/billing" element={<Billing />} />
                  <Route path="/settings/acknowledged-gaps" element={<AcknowledgedGapsReview />} />
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
