import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getAllRepos, getStats, getPipelineRuns } from '../services/github'
import { getFindingsSummary, getFindings, SEVERITY_COLORS, RISK_COLORS } from '../services/defectdojo'
import './DashboardPage.css'

const LANG_COLORS = {
  JavaScript: '#f0db4f', TypeScript: '#3178c6', Python: '#3572A5',
  Go: '#00ADD8', Rust: '#dea584', Swift: '#F05138', Dockerfile: '#384d54',
  HCL: '#5c4ee5', Java: '#b07219', Shell: '#89e051', Ruby: '#701516',
  'C#': '#178600', C: '#555555', 'C++': '#f34b7d',
}

function DashboardPage() {
  const [stats, setStats]       = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [pipeline, setPipeline] = useState({ runs: [], repo: null, loading: true })
  const [ddSummary, setDdSummary] = useState(null)
  const [ddFindings, setDdFindings] = useState([])
  const [ddLoading, setDdLoading]   = useState(true)
  const [ddError, setDdError]       = useState(null)

  useEffect(() => {
    loadData()
    loadPipeline()
    loadDefectDojo()
  }, [])

  async function loadData() {
    setLoading(true)
    setError(null)
    try {
      const repos = await getAllRepos()
      const data = getStats(repos)
      setStats(data)
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data.')
    } finally {
      setLoading(false)
    }
  }

  async function loadPipeline() {
    setPipeline((prev) => ({ ...prev, loading: true }))
    try {
      const data = await getPipelineRuns()
      setPipeline({ runs: data.runs || [], repo: data.repo, loading: false })
    } catch {
      setPipeline({ runs: [], repo: null, loading: false })
    }
  }

  async function loadDefectDojo() {
    setDdLoading(true)
    setDdError(null)
    try {
      const [summaryData, findingsData] = await Promise.all([
        getFindingsSummary(),
        getFindings({ limit: 10 }),
      ])
      setDdSummary(summaryData)
      setDdFindings(findingsData.findings || [])
    } catch (err) {
      setDdError(err.message)
    } finally {
      setDdLoading(false)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  const daysAgo = (dateString) => {
    const diff = Date.now() - new Date(dateString).getTime()
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    if (days === 0) return 'Today'
    if (days === 1) return '1 day ago'
    return `${days} days ago`
  }

  if (loading) {
    return (
      <div className="page-state">
        <div className="spinner"></div>
        <p>Loading security dashboard...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="page-state">
        <div className="error-box">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <div><strong>Error loading data</strong><p>{error}</p></div>
          <button onClick={loadData} className="retry-btn">Retry</button>
        </div>
      </div>
    )
  }

  const stalePercent   = stats.totalRepos > 0 ? (stats.staleRepos.length / stats.totalRepos * 100) : 0
  const issuePercent   = stats.totalRepos > 0 ? (stats.reposWithIssues.length / stats.totalRepos * 100) : 0
  let posture = 'Good', postureClass = 'posture-good'
  if (stalePercent > 50 || issuePercent > 60) { posture = 'Needs Attention'; postureClass = 'posture-warn' }
  if (stalePercent > 75 || issuePercent > 80) { posture = 'Critical'; postureClass = 'posture-critical' }

  const riskColor = ddSummary ? (RISK_COLORS[ddSummary.riskLevel] || RISK_COLORS.clean) : null

  return (
    <div className="dashboard">
      <div className="page-top">
        <div>
          <h1>Security Dashboard</h1>
          <p className="page-desc">Repository security posture and deployment readiness overview</p>
        </div>
      </div>

      {/* KPI Row */}
      <div className="kpi-row">
        <div className="kpi">
          <span className="kpi-val">{stats.totalRepos}</span>
          <span className="kpi-label">Total Repositories</span>
        </div>
        <div className="kpi">
          <span className="kpi-val">{stats.totalIssues}</span>
          <span className="kpi-label">Open Issues</span>
        </div>
        <div className="kpi">
          <span className="kpi-val">
            {ddLoading ? '…' : ddSummary ? ddSummary.summary.total : '—'}
          </span>
          <span className="kpi-label">Active Findings</span>
        </div>
        <div className="kpi">
          {ddLoading ? (
            <div className="posture-badge posture-good">Loading…</div>
          ) : ddSummary ? (
            <div className="posture-badge" style={{ background: riskColor.text, color: '#fff', border: 'none' }}>
              {riskColor.label}
            </div>
          ) : (
            <div className={`posture-badge ${postureClass}`}>{posture}</div>
          )}
          <span className="kpi-label">Security Posture</span>
        </div>
      </div>

      {/* Security Overview Row */}
      <div className="security-row">
        <div className="sec-card">
          <div className="sec-card-icon visibility-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </div>
          <div className="sec-card-body">
            <span className="sec-card-title">Visibility</span>
            <div className="sec-card-stats">
              <span className="sec-stat"><strong>{stats.publicRepos.length}</strong> public</span>
              <span className="sec-stat"><strong>{stats.privateRepos.length}</strong> private</span>
            </div>
          </div>
        </div>
        <div className="sec-card">
          <div className="sec-card-icon iac-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          </div>
          <div className="sec-card-body">
            <span className="sec-card-title">Infrastructure as Code</span>
            <div className="sec-card-stats">
              <span className="sec-stat"><strong>{stats.iacRepos.length}</strong> {stats.iacRepos.length === 1 ? 'repo' : 'repos'}</span>
              <span className="sec-stat-hint">Terraform, Docker, K8s</span>
            </div>
          </div>
        </div>
        <div className="sec-card">
          <div className="sec-card-icon cicd-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          </div>
          <div className="sec-card-body">
            <span className="sec-card-title">CI/CD Pipelines</span>
            <div className="sec-card-stats">
              <span className="sec-stat"><strong>{stats.cicdRepos.length}</strong> {stats.cicdRepos.length === 1 ? 'repo' : 'repos'}</span>
              <span className="sec-stat-hint">GitHub Actions, Jenkins</span>
            </div>
          </div>
        </div>
        <div className="sec-card">
          <div className="sec-card-icon security-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div className="sec-card-body">
            <span className="sec-card-title">Security Tagged</span>
            <div className="sec-card-stats">
              <span className="sec-stat"><strong>{stats.securityRepos.length}</strong> {stats.securityRepos.length === 1 ? 'repo' : 'repos'}</span>
              <span className="sec-stat-hint">OWASP, CVE, SAST topics</span>
            </div>
          </div>
        </div>
      </div>

      {/* Integration Status */}
      <div className="panel integration-status-panel">
        <div className="panel-head">
          <h2>Integration Status</h2>
          <Link to="/integrations" className="panel-action">Manage</Link>
        </div>
        <div className="integrations-grid">
          <div className="integration-item connected">
            <span className="integration-dot active"></span>
            <span className="integration-name">GitHub API</span>
            <span className="integration-badge active">Connected</span>
          </div>
          <div className="integration-item pending">
            <span className="integration-dot pending"></span>
            <span className="integration-name">Security Scanners</span>
            <span className="integration-badge pending">Planned</span>
          </div>
          <div className={`integration-item ${ddError ? 'error' : 'connected'}`}>
            <span className={`integration-dot ${ddError ? 'error' : 'active'}`}></span>
            <span className="integration-name">DefectDojo</span>
            <span className={`integration-badge ${ddError ? 'error' : 'active'}`}>
              {ddLoading ? 'Checking…' : ddError ? 'Error' : 'Connected'}
            </span>
          </div>
          <div className="integration-item pending">
            <span className="integration-dot pending"></span>
            <span className="integration-name">AWS Deployment</span>
            <span className="integration-badge pending">Planned</span>
          </div>
          <div className="integration-item pending">
            <span className="integration-dot pending"></span>
            <span className="integration-name">MCP AI Agent</span>
            <span className="integration-badge pending">Planned</span>
          </div>
        </div>
      </div>

      {/* Main grid */}
      <div className="dash-grid">
        <div className="panel">
          <div className="panel-head">
            <h2>Recent Repository Activity</h2>
            <Link to="/search" className="panel-action">View all</Link>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Repository</th><th>Language</th><th>Visibility</th><th>Issues</th><th>Last Updated</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentRepos.map((repo) => (
                <tr key={repo.id}>
                  <td>
                    <a href={repo.url} target="_blank" rel="noopener noreferrer" className="table-repo-link">
                      <span className="table-repo-name">{repo.name}</span>
                      <span className="table-repo-desc">{repo.description}</span>
                    </a>
                  </td>
                  <td>
                    <span className="lang-pill">
                      <span className="lang-dot" style={{ background: LANG_COLORS[repo.language] || '#999' }}></span>
                      {repo.language}
                    </span>
                  </td>
                  <td>
                    <span className={`visibility-pill ${repo.visibility}`}>
                      {repo.visibility === 'private' ? '🔒 Private' : '🌐 Public'}
                    </span>
                  </td>
                  <td className="num-cell">
                    {repo.openIssues > 0
                      ? <span className="issue-count has-issues">{repo.openIssues}</span>
                      : <span className="issue-count no-issues">0</span>}
                  </td>
                  <td className="date-cell">{daysAgo(repo.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="side-panels">
          {/* Language breakdown */}
          <div className="panel">
            <div className="panel-head"><h2>Language Breakdown</h2></div>
            <div className="lang-breakdown">
              {Object.entries(stats.languageCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([lang, count]) => (
                  <div key={lang} className="lang-row">
                    <span className="lang-row-name">
                      <span className="lang-dot" style={{ background: LANG_COLORS[lang] || '#999' }}></span>
                      {lang}
                    </span>
                    <div className="lang-bar-track">
                      <div className="lang-bar-fill" style={{ width: `${(count / stats.totalRepos) * 100}%`, background: LANG_COLORS[lang] || '#999' }}></div>
                    </div>
                    <span className="lang-row-count">{count}</span>
                  </div>
                ))}
            </div>
          </div>

          {/* Stale repos */}
          {stats.staleRepos.length > 0 && (
            <div className="panel stale-panel">
              <div className="panel-head">
                <h2>Stale Repositories</h2>
                <span className="stale-count">{stats.staleRepos.length}</span>
              </div>
              <div className="stale-list">
                <p className="stale-desc">Not updated in over 90 days. May contain outdated dependencies or unpatched vulnerabilities.</p>
                {stats.staleRepos.slice(0, 5).map((repo) => (
                  <div key={repo.id} className="stale-item">
                    <a href={repo.url} target="_blank" rel="noopener noreferrer" className="stale-name">{repo.name}</a>
                    <span className="stale-date">{daysAgo(repo.updatedAt)}</span>
                  </div>
                ))}
                {stats.staleRepos.length > 5 && (
                  <Link to="/search" className="stale-more">+{stats.staleRepos.length - 5} more</Link>
                )}
              </div>
            </div>
          )}

          {/* Vulnerability Findings — DefectDojo live data */}
          <div className="panel">
            <div className="panel-head">
              <h2>Vulnerability Findings</h2>
              {ddSummary && !ddError && (
                <span className="panel-action" onClick={loadDefectDojo} style={{ cursor: 'pointer' }}>Refresh</span>
              )}
            </div>

            {ddLoading ? (
              <div className="placeholder-body">
                <div className="spinner"></div>
                <p>Loading findings from DefectDojo...</p>
              </div>
            ) : ddError ? (
              <div className="placeholder-body">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <p style={{ color: '#ef4444' }}>{ddError}</p>
                <Link to="/integrations" className="placeholder-link">Configure DefectDojo</Link>
              </div>
            ) : ddSummary && ddSummary.summary.total === 0 ? (
              <div className="placeholder-body">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#16a34a" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <polyline points="9 12 11 14 15 10"/>
                </svg>
                <p style={{ color: '#16a34a' }}>No active findings. Looking clean!</p>
              </div>
            ) : (
              <div className="dd-findings">
                {/* Severity summary bar */}
                {ddSummary && (
                  <div className="dd-summary-row">
                    {['critical','high','medium','low','info'].map(sev => (
                      ddSummary.summary[sev] > 0 && (
                        <div key={sev} className="dd-sev-pill" style={{
                          background: SEVERITY_COLORS[sev].bg,
                          color: SEVERITY_COLORS[sev].text,
                          border: `1px solid ${SEVERITY_COLORS[sev].border}`,
                        }}>
                          <strong>{ddSummary.summary[sev]}</strong> {SEVERITY_COLORS[sev].label}
                        </div>
                      )
                    ))}
                  </div>
                )}
                {/* Recent findings list */}
                <div className="dd-findings-list">
                  {ddFindings.slice(0, 8).map(f => (
                    <div key={f.id} className="dd-finding-row">
                      <span
                        className="dd-sev-dot"
                        style={{ background: SEVERITY_COLORS[f.severity]?.text || '#999' }}
                        title={f.severity}
                      ></span>
                      <div className="dd-finding-info">
                        <span className="dd-finding-title">{f.title}</span>
                        <span className="dd-finding-meta">{f.scanner} {f.file ? `· ${f.file.split('/').pop()}` : ''}</span>
                      </div>
                      {f.notesCount > 0 && (
                        <span className="dd-notes-badge" title={`${f.notesCount} AI triage note(s)`}>🤖 {f.notesCount}</span>
                      )}
                    </div>
                  ))}
                </div>
                {ddSummary && ddSummary.summary.total > 8 && (
                  <p className="dd-more">+{ddSummary.summary.total - 8} more findings in DefectDojo</p>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Pipeline & Deploy row */}
      <div className="dash-grid bottom-grid">
        <div className="panel pipeline-panel">
          <div className="panel-head">
            <h2>CI/CD Pipeline Status</h2>
            {pipeline.repo && pipeline.runs[0] && (
              <a href={pipeline.runs[0].url.replace(/\/runs\/\d+$/, '')} target="_blank" rel="noopener noreferrer" className="panel-action">View all runs</a>
            )}
          </div>
          {pipeline.loading ? (
            <div className="placeholder-body"><div className="spinner"></div><p>Loading pipeline data...</p></div>
          ) : pipeline.runs.length === 0 ? (
            <div className="placeholder-body">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
              </svg>
              <p>No pipeline runs found. Push code to trigger GitHub Actions workflows.</p>
            </div>
          ) : (
            <div className="pipeline-runs">
              {pipeline.runs.slice(0, 6).map((run) => (
                <a key={run.id} href={run.url} target="_blank" rel="noopener noreferrer" className="pipeline-run">
                  <span className={`pipeline-status-dot ${run.conclusion || run.status}`}></span>
                  <div className="pipeline-run-info">
                    <span className="pipeline-run-name">{run.name}</span>
                    <span className="pipeline-run-meta">{run.branch} · {run.commit} · {run.actor}</span>
                  </div>
                  <div className="pipeline-run-right">
                    <span className={`pipeline-conclusion ${run.conclusion || run.status}`}>{run.conclusion || run.status}</span>
                    <span className="pipeline-run-time">{daysAgo(run.createdAt)}</span>
                  </div>
                </a>
              ))}
            </div>
          )}
        </div>
        <div className="panel placeholder-panel">
          <div className="panel-head"><h2>AWS Deployment Monitor</h2></div>
          <div className="placeholder-body">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
            <p>Terraform and AWS integration will show EC2 instances, security groups, and deployment configs.</p>
            <span className="placeholder-tag">Coming soon</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
