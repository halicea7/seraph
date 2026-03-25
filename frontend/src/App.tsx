import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from '@/contexts/AuthContext'
import { ThemeProvider } from '@/contexts/ThemeContext'
import { AINarrativeProvider } from '@/contexts/AINarrativeContext'
import Layout from '@/components/Layout'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import AuditBuilder from '@/pages/AuditBuilder'
import PentestWorkbench from '@/pages/PentestWorkbench'
import Reports from '@/pages/Reports'
import Settings from '@/pages/Settings'
import C2Console from '@/pages/C2Console'
import CredentialVault from '@/pages/CredentialVault'
import OSINTModule from '@/pages/OSINTModule'
import NetworkMap from '@/pages/NetworkMap'
import PasswordAuditing from '@/pages/PasswordAuditing'
import Playbooks from '@/pages/Playbooks'
import Guide from '@/pages/Guide'
import VulnTracker from '@/pages/VulnTracker'
import LogAnalysis from '@/pages/LogAnalysis'
import AllScans from '@/pages/AllScans'
import AllFindings from '@/pages/AllFindings'
import Listeners from '@/pages/Listeners'
import Agents from '@/pages/Agents'
import { Loader } from 'lucide-react'

function ProtectedRoutes() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ background: '#05080d' }}>
        <Loader size={24} className="animate-spin text-cyan-500" />
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" replace />
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="audit" element={<AuditBuilder />} />
        <Route path="pentest" element={<PentestWorkbench />} />
        <Route path="osint" element={<OSINTModule />} />
        <Route path="network" element={<NetworkMap />} />
        <Route path="cracking" element={<PasswordAuditing />} />
        <Route path="playbooks" element={<Playbooks />} />
        <Route path="guide" element={<Guide />} />
        <Route path="vulns" element={<VulnTracker />} />
        <Route path="logs" element={<LogAnalysis />} />
        <Route path="scans" element={<AllScans />} />
        <Route path="findings" element={<AllFindings />} />
        <Route path="listeners" element={<Listeners />} />
        <Route path="agents" element={<Agents />} />
        <Route path="c2" element={<C2Console />} />
        <Route path="vault" element={<CredentialVault />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  )
}

function AuthGate() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen" style={{ background: '#05080d' }}>
        <Loader size={24} className="animate-spin text-cyan-500" />
      </div>
    )
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={user ? <Navigate to="/" replace /> : <Login />}
      />
      <Route path="/*" element={<ProtectedRoutes />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <AINarrativeProvider>
            <AuthGate />
          </AINarrativeProvider>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
