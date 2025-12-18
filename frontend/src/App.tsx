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

function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />

        {/* Protected routes */}
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/accounts" element={<Accounts />} />
                  <Route path="/detections" element={<Detections />} />
                  <Route path="/coverage" element={<Coverage />} />
                  <Route path="/gaps" element={<Gaps />} />
                  <Route path="/settings/team" element={<TeamManagement />} />
                  <Route path="/settings/api-keys" element={<APIKeys />} />
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
