import { useState, useEffect } from 'react'
import { apiFetch } from '../services/api'
import { testDefectDojoConnection } from '../services/defectdojo'
import './IntegrationsPage.css'

function IntegrationsPage() {
  // GitHub state
  const [org, setOrg]                   = useState('')
  const [token, setToken]               = useState('')
  const [tokenPreview, setTokenPreview] = useState('')
  const [hasToken, setHasToken]         = useState(false)

  // DefectDojo state
  const [ddUrl, setDdUrl]               = useState('')
  const [ddKey, setDdKey]               = useState('')
  const [ddKeyPreview, setDdKeyPreview] = useState('')
  const [hasApiKey, setHasApiKey]       = useState(false)
  const [ddTestResult, setDdTestResult] = useState(null)
  const [ddTesting, setDdTesting]       = useState(false)

  const [loading, setLoading]   = useState(true)
  const [saving, setSaving]     = useState(false)
  const [testing, setTesting]   = useState(false)
  const [message, setMessage]   = useState(null)
  const [testResult, setTestResult] = useState(null)

  useEffect(() => { loadSettings() }, [])

  async function loadSettings() {
    setLoading(true)
    try {
      const data = await apiFetch('/settings/integrations')
      setOrg(data.github.org)
      setHasToken(data.github.hasToken)
      setTokenPreview(data.github.tokenPreview)
      if (data.defectdojo) {
        setDdUrl(data.defectdojo.url || '')
        setHasApiKey(data.defectdojo.hasApiKey)
        setDdKeyPreview(data.defectdojo.apiKeyPreview || '')
      }
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setLoading(false)
    }
  }

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setMessage(null)
    setTestResult(null)
    try {
      const body = { github_org: org }
      if (token) body.github_token = token
      await apiFetch('/settings/integrations', {
        method: 'PUT',
        body: JSON.stringify(body),
      })
      setMessage({ type: 'success', text: 'GitHub settings saved.' })
      setToken('')
      loadSettings()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setSaving(false)
    }
  }

  async function handleSaveDefectDojo(e) {
    e.preventDefault()
    setSaving(true)
    setMessage(null)
    setDdTestResult(null)
    try {
      const body = {}
      if (ddUrl) body.defectdojo_url = ddUrl
      if (ddKey) body.defectdojo_api_key = ddKey
      await apiFetch('/settings/integrations', {
        method: 'PUT',
        body: JSON.stringify(body),
      })
      setMessage({ type: 'success', text: 'DefectDojo settings saved.' })
      setDdKey('')
      loadSettings()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setSaving(false)
    }
  }

  async function handleTest() {
    setTesting(true)
    setTestResult(null)
    setMessage(null)
    try {
      const data = await apiFetch('/settings/integrations/test', { method: 'POST' })
      setTestResult(data)
    } catch (err) {
      setTestResult({ success: false, error: err.message })
    } finally {
      setTesting(false)
    }
  }

  async function handleTestDefectDojo() {
    setDdTesting(true)
    setDdTestResult(null)
    try {
      const data = await testDefectDojoConnection()
      setDdTestResult(data)
    } catch (err) {
      setDdTestResult({ connected: false, message: err.message })
    } finally {
      setDdTesting(false)
    }
  }

  if (loading) {
    return (
      <div className="page-state">
        <div className="spinner"></div>
        <p>Loading settings...</p>
      </div>
    )
  }

  return (
    <div className="integrations-page">
      <div className="page-top">
        <h1>Integrations</h1>
        <p className="page-desc">Configure external tool connections</p>
      </div>

      {message && (
        <div className={`admin-alert ${message.type}`}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            {message.type === 'success' ? (
              <><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></>
            ) : (
              <><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></>
            )}
          </svg>
          {message.text}
        </div>
      )}

      {/* GitHub Integration */}
      <div className="panel">
        <div className="panel-head">
          <div className="integration-head">
            <div className="integration-icon github">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
              </svg>
            </div>
            <div>
              <h2>GitHub</h2>
              <span className="integration-subtitle">Browse organization or user repositories</span>
            </div>
          </div>
          <div className="connection-status">
            {hasToken && org ? (
              <span className="status-pill connected">Connected</span>
            ) : (
              <span className="status-pill disconnected">Not configured</span>
            )}
          </div>
        </div>

        <form className="integration-form" onSubmit={handleSave}>
          <div className="form-field">
            <label htmlFor="github-org">Organization or username</label>
            <input
              id="github-org" type="text" value={org}
              onChange={(e) => setOrg(e.target.value)}
              placeholder="e.g. google, facebook, mmill210-lang"
            />
            <span className="form-hint">The GitHub organization or personal username whose repos will appear in ToolVault.</span>
          </div>
          <div className="form-field">
            <label htmlFor="github-token">Personal access token</label>
            <input
              id="github-token" type="password" value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={hasToken ? `Current: ${tokenPreview}` : 'ghp_... or github_pat_...'}
            />
            <span className="form-hint">
              A classic token with <code>repo</code> scope (or <code>public_repo</code> for public repos only).{' '}
              <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer">Generate one here</a>
            </span>
          </div>
          <div className="form-actions">
            <button type="submit" className="save-btn" disabled={saving}>{saving ? 'Saving...' : 'Save settings'}</button>
            <button type="button" className="test-btn" onClick={handleTest} disabled={testing || !org}>{testing ? 'Testing...' : 'Test connection'}</button>
          </div>
        </form>

        {testResult && (
          <div className={`test-result ${testResult.success ? 'success' : 'error'}`}>
            {testResult.success ? (
              <div className="test-success">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                <div>
                  <strong>Connected to {testResult.org.name}</strong>
                  <p>{testResult.org.publicRepos} public repositories{testResult.org.description ? ` — ${testResult.org.description}` : ''}</p>
                </div>
              </div>
            ) : (
              <div className="test-error">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                <div><strong>Connection failed</strong><p>{testResult.error}</p></div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* DefectDojo Integration */}
      <div className="panel" style={{ marginTop: '20px' }}>
        <div className="panel-head">
          <div className="integration-head">
            <div className="integration-icon" style={{ background: '#1a1a2e', color: '#e94560', border: '1px solid #e94560', borderRadius: '8px', width: '36px', height: '36px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '16px', fontWeight: 'bold' }}>
              DD
            </div>
            <div>
              <h2>DefectDojo</h2>
              <span className="integration-subtitle">Vulnerability management and AI triage findings</span>
            </div>
          </div>
          <div className="connection-status">
            {hasApiKey && ddUrl ? (
              <span className="status-pill connected">Configured</span>
            ) : (
              <span className="status-pill disconnected">Not configured</span>
            )}
          </div>
        </div>

        <form className="integration-form" onSubmit={handleSaveDefectDojo}>
          <div className="form-field">
            <label htmlFor="dd-url">DefectDojo URL</label>
            <input
              id="dd-url" type="text" value={ddUrl}
              onChange={(e) => setDdUrl(e.target.value)}
              placeholder="http://your-defectdojo-instance.com"
            />
            <span className="form-hint">The base URL of your DefectDojo instance (no trailing slash).</span>
          </div>
          <div className="form-field">
            <label htmlFor="dd-key">API Key</label>
            <input
              id="dd-key" type="password" value={ddKey}
              onChange={(e) => setDdKey(e.target.value)}
              placeholder={hasApiKey ? `Current: ${ddKeyPreview}` : 'Your DefectDojo API v2 key'}
            />
            <span className="form-hint">
              Found in DefectDojo under your username → <strong>API v2 key</strong>.
            </span>
          </div>
          <div className="form-actions">
            <button type="submit" className="save-btn" disabled={saving}>{saving ? 'Saving...' : 'Save settings'}</button>
            <button type="button" className="test-btn" onClick={handleTestDefectDojo} disabled={ddTesting || (!hasApiKey && !ddKey)}>
              {ddTesting ? 'Testing...' : 'Test connection'}
            </button>
          </div>
        </form>

        {ddTestResult && (
          <div className={`test-result ${ddTestResult.connected ? 'success' : 'error'}`}>
            {ddTestResult.connected ? (
              <div className="test-success">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                <div><strong>DefectDojo connected</strong><p>{ddTestResult.message}</p></div>
              </div>
            ) : (
              <div className="test-error">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                <div><strong>Connection failed</strong><p>{ddTestResult.message}</p></div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default IntegrationsPage
