import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router'
import { Toaster } from 'react-hot-toast'
import { AuthProvider } from './contexts/AuthContext'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import ScrollToTop from './components/ScrollToTop'

// Critical path pages (loaded immediately)
import Landing from './pages/Landing'
import Login from './pages/Login'
import Signup from './pages/Signup'
import AuthCallback from './pages/AuthCallback'

// Loading fallback component
const PageLoader = () => (
  <div className="flex items-center justify-center min-h-screen bg-gray-900">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
  </div>
)

// Lazy-loaded pages (code-split for better performance)
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Accounts = lazy(() => import('./pages/Accounts'))
const Detections = lazy(() => import('./pages/Detections'))
const Coverage = lazy(() => import('./pages/Coverage'))
const Compliance = lazy(() => import('./pages/Compliance'))
const Gaps = lazy(() => import('./pages/Gaps'))
const TechniqueDetail = lazy(() => import('./pages/TechniqueDetail'))
const Reports = lazy(() => import('./pages/Reports'))
const TeamManagement = lazy(() => import('./pages/TeamManagement'))
const APIKeys = lazy(() => import('./pages/APIKeys'))
const AuditLogs = lazy(() => import('./pages/AuditLogs'))
const Profile = lazy(() => import('./pages/Profile'))
const OrgSecurity = lazy(() => import('./pages/OrgSecurity'))
const Billing = lazy(() => import('./pages/Billing'))
const AcknowledgedGapsReview = lazy(() => import('./pages/AcknowledgedGapsReview'))
const ComplianceHistory = lazy(() => import('./pages/ComplianceHistory'))
const Terms = lazy(() => import('./pages/Terms'))
const Privacy = lazy(() => import('./pages/Privacy'))
const Security = lazy(() => import('./pages/Security'))
const ComplianceInfo = lazy(() => import('./pages/ComplianceInfo'))
const Support = lazy(() => import('./pages/Support'))

// Organisation pages (lazy)
const Organizations = lazy(() => import('./pages/Organizations'))
const ConnectOrganization = lazy(() => import('./pages/ConnectOrganization'))
const OrganizationDashboard = lazy(() => import('./pages/OrganizationDashboard'))
const OrganizationMembers = lazy(() => import('./pages/OrganizationMembers'))

// Documentation pages (lazy)
const DocsIndex = lazy(() => import('./pages/docs/DocsIndex').then(m => ({ default: m.DocsIndex })))
const DocsPage = lazy(() => import('./pages/docs/DocsPage').then(m => ({ default: m.DocsPage })))

// Admin Portal pages (lazy - rarely accessed)
const AdminAuthProvider = lazy(() => import('./components/AdminAuthProvider').then(m => ({ default: m.AdminAuthProvider })))
const AdminLogin = lazy(() => import('./pages/admin/AdminLogin'))
const AdminDashboard = lazy(() => import('./pages/admin/AdminDashboard'))
const AdminSettings = lazy(() => import('./pages/admin/AdminSettings'))
const AdminOrganizations = lazy(() => import('./pages/admin/AdminOrganizations'))
const AdminUsers = lazy(() => import('./pages/admin/AdminUsers'))
const AdminFingerprints = lazy(() => import('./pages/admin/AdminFingerprints'))
const AdminAuditLogs = lazy(() => import('./pages/admin/AdminAuditLogs'))
const AdminBilling = lazy(() => import('./pages/admin/AdminBilling'))
const AdminAdmins = lazy(() => import('./pages/admin/AdminAdmins'))
const AdminMitreData = lazy(() => import('./pages/admin/AdminMitreData'))
const AdminProfile = lazy(() => import('./pages/admin/AdminProfile'))

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
      <ScrollToTop />
      <Suspense fallback={<PageLoader />}>
        <Routes>
          {/* Public routes (critical path - no lazy loading) */}
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/auth/callback" element={<AuthCallback />} />

          {/* Public routes (lazy loaded) */}
          <Route path="/terms" element={<Terms />} />
          <Route path="/privacy" element={<Privacy />} />
          <Route path="/security" element={<Security />} />
          <Route path="/compliance-info" element={<ComplianceInfo />} />
          <Route path="/support" element={<Support />} />

          {/* Documentation routes (public, lazy) */}
          <Route path="/docs" element={<DocsIndex />} />
          <Route path="/docs/:slug" element={<DocsPage />} />

          {/* Admin Portal routes (separate auth with session restoration) */}
          <Route path="/admin/*" element={
            <AdminAuthProvider>
              <Routes>
                <Route index element={<Navigate to="login" replace />} />
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
      </Suspense>
    </AuthProvider>
  )
}

export default App
