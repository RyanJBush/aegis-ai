import { useEffect, useState } from 'react'
import {
  Navigate,
  Route,
  BrowserRouter as Router,
  Routes,
} from 'react-router-dom'

import { api, setAuthToken } from './api'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import AppInterfacePage from './pages/AppInterfacePage'
import DashboardPage from './pages/DashboardPage'
import LoginPage from './pages/LoginPage'
import ScanResultsPage from './pages/ScanResultsPage'
import VulnerabilityDetailPage from './pages/VulnerabilityDetailPage'

function App() {
  const [token, setToken] = useState(localStorage.getItem('aegis_token') ?? '')
  const [me, setMe] = useState(null)
  const [appData, setAppData] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [scanForm, setScanForm] = useState({ target: '', content: '' })

  const refreshAppData = async () => {
    const { data } = await api.get('/api/app/data')
    setAppData(data)
  }

  const refreshVulnerabilities = async () => {
    try {
      const { data } = await api.get('/api/vulnerabilities')
      setVulnerabilities(data)
    } catch {
      setVulnerabilities([])
    }
  }

  useEffect(() => {
    if (!token) {
      setAuthToken(null)
      return
    }

    setAuthToken(token)
    let active = true

    const load = async () => {
      try {
        const [
          { data: meData },
          { data: appDataRecords },
          vulnerabilityResponse,
        ] = await Promise.all([
          api.get('/api/auth/me'),
          api.get('/api/app/data'),
          api.get('/api/vulnerabilities').catch(() => ({ data: [] })),
        ])
        if (active) {
          setMe(meData)
          setAppData(appDataRecords)
          setVulnerabilities(vulnerabilityResponse.data)
        }
      } catch {
        if (active) {
          setMe(null)
          setAppData([])
          setVulnerabilities([])
        }
      }
    }

    void load()
    return () => {
      active = false
    }
  }, [token])

  const handleLogin = (newToken) => {
    setToken(newToken)
    localStorage.setItem('aegis_token', newToken)
  }

  const handleLogout = () => {
    setToken('')
    setMe(null)
    setAppData([])
    setVulnerabilities([])
    localStorage.removeItem('aegis_token')
    setAuthToken(null)
  }

  const runScan = async (event) => {
    event.preventDefault()
    await api.post('/api/scan', scanForm)
    setScanForm({ target: '', content: '' })
    await refreshVulnerabilities()
  }

  return (
    <Router>
      <Routes>
        <Route
          path="/"
          element={<Layout token={token} onLogout={handleLogout} />}
        >
          <Route path="login" element={<LoginPage onLogin={handleLogin} />} />

          <Route
            path="dashboard"
            element={
              <ProtectedRoute token={token}>
                <DashboardPage me={me} vulnerabilities={vulnerabilities} />
              </ProtectedRoute>
            }
          />
          <Route
            path="app"
            element={
              <ProtectedRoute token={token}>
                <AppInterfacePage
                  appData={appData}
                  refreshAppData={refreshAppData}
                />
              </ProtectedRoute>
            }
          />
          <Route
            path="scan-results"
            element={
              <ProtectedRoute token={token}>
                <ScanResultsPage
                  vulnerabilities={vulnerabilities}
                  runScan={runScan}
                  scanForm={scanForm}
                  setScanForm={setScanForm}
                />
              </ProtectedRoute>
            }
          />
          <Route
            path="vulnerabilities/:id"
            element={
              <ProtectedRoute token={token}>
                <VulnerabilityDetailPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="*"
            element={<Navigate to={token ? '/dashboard' : '/login'} replace />}
          />
        </Route>
      </Routes>
    </Router>
  )
}

export default App
