import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Navbar from './components/Navbar'
import LoginPage from './pages/LoginPage'
import SearchPage from './pages/SearchPage'
import DashboardPage from './pages/DashboardPage'
import AdminPage from './pages/AdminPage'
import IntegrationsPage from './pages/IntegrationsPage'
import SettingsPage from './pages/SettingsPage'
import { getStoredUser, clearToken, apiFetch } from './services/api'
import './App.css'

function App() {
  // Check if user was already logged in (token in sessionStorage)
  const [user, setUser] = useState(getStoredUser())
  const [mustChangePassword, setMustChangePassword] = useState(false)

  // Theme state — persisted to sessionStorage
  const [theme, setTheme] = useState(() => {
    return sessionStorage.getItem('toolVaultTheme') || 'light'
  })

  const isLoggedIn = !!user
  const isAdmin = user?.role === 'admin'

  // Apply theme to the document
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    sessionStorage.setItem('toolVaultTheme', theme)
  }, [theme])

  // Check if user needs to change their password (default admin password)
  useEffect(() => {
    if (isLoggedIn) {
      apiFetch('/auth/me')
        .then((data) => {
          setMustChangePassword(data.mustChangePassword || false)
        })
        .catch(() => {
          // Silently ignore — user can still use the app
        })
    }
  }, [isLoggedIn])

  const handleLogin = (userData) => {
    setUser(userData)
  }

  const handleLogout = () => {
    clearToken()
    setUser(null)
    setMustChangePassword(false)
  }

  const handleThemeChange = (newTheme) => {
    setTheme(newTheme)
  }

  const handlePasswordChanged = () => {
    setMustChangePassword(false)
  }

  return (
    <div className="app-layout">
      {isLoggedIn && <Navbar user={user} onLogout={handleLogout} mustChangePassword={mustChangePassword} />}
      <main className={isLoggedIn ? 'main-content' : 'main-content full-width'}>
        <Routes>
          <Route path="/login" element={isLoggedIn ? <Navigate to="/dashboard" /> : <LoginPage onLogin={handleLogin} />} />
          <Route path="/dashboard" element={isLoggedIn ? <DashboardPage /> : <Navigate to="/login" />} />
          <Route path="/search" element={isLoggedIn ? <SearchPage /> : <Navigate to="/login" />} />
          <Route path="/settings" element={isLoggedIn ? <SettingsPage onThemeChange={handleThemeChange} currentTheme={theme} onPasswordChanged={handlePasswordChanged} /> : <Navigate to="/login" />} />
          <Route path="/admin" element={isLoggedIn && isAdmin ? <AdminPage /> : <Navigate to={isLoggedIn ? '/dashboard' : '/login'} />} />
          <Route path="/integrations" element={isLoggedIn && isAdmin ? <IntegrationsPage /> : <Navigate to={isLoggedIn ? '/dashboard' : '/login'} />} />
          <Route path="*" element={<Navigate to={isLoggedIn ? '/dashboard' : '/login'} />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
