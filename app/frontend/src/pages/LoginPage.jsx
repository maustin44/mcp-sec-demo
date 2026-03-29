import { useState } from 'react'
import { apiFetch, setToken, setStoredUser } from '../services/api'
import './LoginPage.css'

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (!username.trim() || !password.trim()) {
      setError('Username and password are required.')
      return
    }

    setLoading(true)
    setError('')

    try {
      const data = await apiFetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      })

      // Save the token and user info
      setToken(data.token)
      setStoredUser(data.user)
      onLogin(data.user)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <div className="login-logo">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 19.5A2.5 2.5 0 016.5 17H20"/>
              <path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/>
            </svg>
          </div>
          <h1>Sign in to ToolVault</h1>
          <p>Access your organization's development tools</p>
        </div>

        {error && (
          <div className="login-alert">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            {error}
          </div>
        )}

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input id="username" type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Enter your username" autoComplete="username" />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter your password" autoComplete="current-password" />
          </div>
          <button type="submit" className="login-submit" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <div className="login-note">
          Default login — admin / admin123
        </div>
      </div>
    </div>
  )
}

export default LoginPage
