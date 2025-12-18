import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Accounts from './pages/Accounts'
import Detections from './pages/Detections'
import Coverage from './pages/Coverage'
import Gaps from './pages/Gaps'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/accounts" element={<Accounts />} />
        <Route path="/detections" element={<Detections />} />
        <Route path="/coverage" element={<Coverage />} />
        <Route path="/gaps" element={<Gaps />} />
      </Routes>
    </Layout>
  )
}

export default App
