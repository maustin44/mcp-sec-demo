import { useState, useEffect } from 'react'
import { apiFetch } from '../services/api'
import './AdminPage.css'

function AdminPage() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [message, setMessage] = useState(null)

  // New user form
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('user')
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    loadUsers()
  }, [])

  async function loadUsers() {
    setLoading(true)
    setError(null)
    try {
      const data = await apiFetch('/auth/users')
      setUsers(data.users)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleCreateUser(e) {
    e.preventDefault()
    setCreating(true)
    setMessage(null)
    setError(null)

    try {
      await apiFetch('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ username: newUsername, password: newPassword, role: newRole }),
      })
      setMessage(`Account "${newUsername}" created successfully.`)
      setNewUsername('')
      setNewPassword('')
      setNewRole('user')
      loadUsers()
    } catch (err) {
      setError(err.message)
    } finally {
      setCreating(false)
    }
  }

  async function handleDeleteUser(userId, username) {
    if (!window.confirm(`Delete user "${username}"? This cannot be undone.`)) return

    setMessage(null)
    setError(null)
    try {
      await apiFetch(`/auth/users/${userId}`, { method: 'DELETE' })
      setMessage(`User "${username}" deleted.`)
      loadUsers()
    } catch (err) {
      setError(err.message)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
    })
  }

  return (
    <div className="admin-page">
      <div className="page-top">
        <h1>Manage users</h1>
        <p className="page-desc">Create accounts and assign roles</p>
      </div>

      {message && (
        <div className="admin-alert success">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          {message}
        </div>
      )}

      {error && (
        <div className="admin-alert error">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          {error}
        </div>
      )}

      {/* Create new user */}
      <div className="panel">
        <div className="panel-head">
          <h2>Create new account</h2>
        </div>
        <form className="create-form" onSubmit={handleCreateUser}>
          <div className="field-row">
            <div className="field">
              <label>Username</label>
              <input type="text" value={newUsername} onChange={(e) => setNewUsername(e.target.value)} placeholder="min. 3 characters" />
            </div>
            <div className="field">
              <label>Password</label>
              <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="min. 8 characters" />
            </div>
            <div className="field">
              <label>Role</label>
              <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <button type="submit" className="create-btn" disabled={creating}>
              {creating ? 'Creating...' : 'Create account'}
            </button>
          </div>
        </form>
      </div>

      {/* User list */}
      <div className="panel">
        <div className="panel-head">
          <h2>All accounts ({users.length})</h2>
          <button className="refresh-btn" onClick={loadUsers} disabled={loading}>Refresh</button>
        </div>

        {loading ? (
          <div className="panel-loading">Loading users...</div>
        ) : (
          <table className="users-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="user-cell">
                    <span className="user-cell-avatar">{u.username.charAt(0).toUpperCase()}</span>
                    {u.username}
                  </td>
                  <td>
                    <span className={`role-badge ${u.role}`}>{u.role}</span>
                  </td>
                  <td className="date-cell">{formatDate(u.created_at)}</td>
                  <td className="action-cell">
                    <button className="delete-btn" onClick={() => handleDeleteUser(u.id, u.username)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default AdminPage
