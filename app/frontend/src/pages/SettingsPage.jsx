import { useState, useEffect } from 'react'
import { apiFetch, getStoredUser } from '../services/api'
import './SettingsPage.css'

function SettingsPage({ onThemeChange, currentTheme, onPasswordChanged }) {
  const user = getStoredUser()

  // Password change form
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)
  const [passwordMessage, setPasswordMessage] = useState(null)

  // Theme
  const [theme, setTheme] = useState(currentTheme || 'light')

  function handleThemeChange(newTheme) {
    setTheme(newTheme)
    onThemeChange(newTheme)
  }

  async function handlePasswordChange(e) {
    e.preventDefault()
    setPasswordMessage(null)

    if (newPassword.length < 8) {
      setPasswordMessage({ type: 'error', text: 'New password must be at least 8 characters.' })
      return
    }

    if (newPassword !== confirmPassword) {
      setPasswordMessage({ type: 'error', text: 'New passwords do not match.' })
      return
    }

    if (currentPassword === newPassword) {
      setPasswordMessage({ type: 'error', text: 'New password must be different from your current password.' })
      return
    }

    setChangingPassword(true)
    try {
      await apiFetch('/auth/me/password', {
        method: 'PUT',
        body: JSON.stringify({ currentPassword, newPassword }),
      })
      setPasswordMessage({ type: 'success', text: 'Password changed successfully.' })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      // Notify parent that password was changed (clears the notification badge)
      if (onPasswordChanged) onPasswordChanged()
    } catch (err) {
      setPasswordMessage({ type: 'error', text: err.message })
    } finally {
      setChangingPassword(false)
    }
  }

  return (
    <div className="settings-page">
      <div className="page-top">
        <h1>Settings</h1>
        <p className="page-desc">Your profile, security, and preferences</p>
      </div>

      {/* Profile Info */}
      <div className="panel">
        <div className="panel-head">
          <h2>Profile</h2>
        </div>
        <div className="settings-profile">
          <div className="profile-avatar-large">
            {user?.username?.charAt(0).toUpperCase()}
          </div>
          <div className="profile-details">
            <div className="profile-row">
              <span className="profile-label">Username</span>
              <span className="profile-value">{user?.username}</span>
            </div>
            <div className="profile-row">
              <span className="profile-label">Role</span>
              <span className={`role-badge ${user?.role}`}>{user?.role}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Change Password */}
      <div className="panel">
        <div className="panel-head">
          <h2>Change Password</h2>
        </div>
        <form className="settings-form" onSubmit={handlePasswordChange}>
          {passwordMessage && (
            <div className={`settings-alert ${passwordMessage.type}`}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                {passwordMessage.type === 'success' ? (
                  <><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></>
                ) : (
                  <><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></>
                )}
              </svg>
              {passwordMessage.text}
            </div>
          )}
          <div className="settings-field">
            <label htmlFor="current-pw">Current password</label>
            <input
              id="current-pw"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Enter your current password"
              autoComplete="current-password"
            />
          </div>
          <div className="settings-field">
            <label htmlFor="new-pw">New password</label>
            <input
              id="new-pw"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Minimum 8 characters"
              autoComplete="new-password"
            />
          </div>
          <div className="settings-field">
            <label htmlFor="confirm-pw">Confirm new password</label>
            <input
              id="confirm-pw"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Re-enter new password"
              autoComplete="new-password"
            />
          </div>
          <button
            type="submit"
            className="settings-save-btn"
            disabled={changingPassword || !currentPassword || !newPassword || !confirmPassword}
          >
            {changingPassword ? 'Changing...' : 'Change password'}
          </button>
        </form>
      </div>

      {/* Theme */}
      <div className="panel">
        <div className="panel-head">
          <h2>Appearance</h2>
        </div>
        <div className="theme-options">
          <button
            className={`theme-card ${theme === 'light' ? 'active' : ''}`}
            onClick={() => handleThemeChange('light')}
          >
            <div className="theme-preview light-preview">
              <div className="tp-sidebar"></div>
              <div className="tp-content">
                <div className="tp-bar"></div>
                <div className="tp-block"></div>
                <div className="tp-block short"></div>
              </div>
            </div>
            <span className="theme-label">Light</span>
          </button>
          <button
            className={`theme-card ${theme === 'dark' ? 'active' : ''}`}
            onClick={() => handleThemeChange('dark')}
          >
            <div className="theme-preview dark-preview">
              <div className="tp-sidebar"></div>
              <div className="tp-content">
                <div className="tp-bar"></div>
                <div className="tp-block"></div>
                <div className="tp-block short"></div>
              </div>
            </div>
            <span className="theme-label">Dark</span>
          </button>
        </div>
      </div>
    </div>
  )
}

export default SettingsPage
