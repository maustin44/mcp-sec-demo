import { useState, useEffect } from 'react'
import { searchRepos, filterByLanguage, getLanguages } from '../services/github'
import { triggerScan, pollScanUntilDone, RUN_STATUS, RUN_CONCLUSION } from '../services/scan_trigger'
import './SearchPage.css'

const LANG_COLORS = {
  JavaScript: '#f0db4f', TypeScript: '#3178c6', Python: '#3572A5',
  Go: '#00ADD8', Rust: '#dea584', Swift: '#F05138',
  Dockerfile: '#384d54', HCL: '#5c4ee5',
}

function ScanModal({ repo, onClose }) {
  const [phase, setPhase]     = useState('confirm') // confirm | running | done | error
  const [runData, setRunData] = useState(null)
  const [jobs, setJobs]       = useState([])
  const [error, setError]     = useState(null)

  async function startScan() {
    setPhase('running')
    setError(null)
    try {
      const result = await triggerScan({ targetRepo: repo.name, targetUrl: repo.url })
      setRunData(result)

      if (result.runId) {
        pollScanUntilDone(result.runId, (status) => {
          setRunData(status)
          setJobs(status.jobs || [])
          if (status.status === 'completed') setPhase('done')
        })
      } else {
        // No run ID returned yet — show success without polling
        setPhase('done')
      }
    } catch (err) {
      setError(err.message)
      setPhase('error')
    }
  }

  const conclusionColor = runData?.conclusion
    ? (RUN_CONCLUSION[runData.conclusion]?.color || '#6b7280')
    : '#2563eb'

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && phase !== 'running' && onClose()}>
      <div className="modal">
        <div className="modal-head">
          <h2>
            {phase === 'confirm' && '🔍 Scan Repository'}
            {phase === 'running' && '⚙️ Scan Running...'}
            {phase === 'done'    && (runData?.conclusion === 'success' ? '✅ Scan Complete' : '⚠️ Scan Finished')}
            {phase === 'error'   && '❌ Scan Failed'}
          </h2>
          {phase !== 'running' && (
            <button className="modal-close" onClick={onClose}>✕</button>
          )}
        </div>

        <div className="modal-body">
          {phase === 'confirm' && (
            <>
              <p>This will trigger a full security scan of <strong>{repo.name}</strong> using:</p>
              <ul className="scan-tools-list">
                <li>🔬 <strong>SonarCloud</strong> — static analysis (SAST)</li>
                <li>🏗️ <strong>Checkov</strong> — infrastructure misconfigurations</li>
                <li>📦 <strong>npm audit</strong> — dependency vulnerabilities</li>
                <li>🌐 <strong>OWASP ZAP</strong> — dynamic scanning (DAST)</li>
                <li>🤖 <strong>Claude AI</strong> — contextual triage of all findings</li>
              </ul>
              <p className="scan-note">Results will appear in DefectDojo and on the dashboard. The scan takes approximately 5–10 minutes.</p>
            </>
          )}

          {(phase === 'running' || phase === 'done') && (
            <>
              <div className="scan-status-row">
                <div className="scan-status-indicator" style={{ background: conclusionColor }}></div>
                <div>
                  <strong style={{ color: conclusionColor }}>
                    {phase === 'running' ? 'Scan in progress...' : `${RUN_CONCLUSION[runData?.conclusion]?.label || 'Completed'}`}
                  </strong>
                  {runData?.url && (
                    <a href={runData.url} target="_blank" rel="noopener noreferrer" className="run-link">
                      View in GitHub Actions →
                    </a>
                  )}
                </div>
              </div>

              {jobs.length > 0 && (
                <div className="scan-jobs">
                  {jobs.map((job, i) => {
                    const color = job.conclusion
                      ? (RUN_CONCLUSION[job.conclusion]?.color || '#6b7280')
                      : (job.status === 'in_progress' ? '#2563eb' : '#6b7280')
                    return (
                      <div key={i} className="scan-job-row">
                        <span className="scan-job-dot" style={{ background: color }}></span>
                        <span className="scan-job-name">{job.name}</span>
                        <span className="scan-job-status" style={{ color }}>
                          {job.conclusion || job.status}
                        </span>
                      </div>
                    )
                  })}
                </div>
              )}

              {phase === 'running' && (
                <p className="scan-running-note">This window will update as jobs complete. You can also close this and check the dashboard later.</p>
              )}

              {phase === 'done' && (
                <p className="scan-running-note">Findings have been pushed to DefectDojo and AI triage is complete. Refresh the dashboard to see results.</p>
              )}
            </>
          )}

          {phase === 'error' && (
            <div className="scan-error-box">
              <p>{error}</p>
              <p className="scan-note">Make sure your GitHub token has the <code>workflow</code> scope enabled.</p>
            </div>
          )}
        </div>

        <div className="modal-foot">
          {phase === 'confirm' && (
            <>
              <button className="cancel-btn" onClick={onClose}>Cancel</button>
              <button className="scan-btn" onClick={startScan}>Start Scan</button>
            </>
          )}
          {phase === 'running' && (
            <button className="cancel-btn" onClick={onClose}>Close (scan continues in background)</button>
          )}
          {(phase === 'done' || phase === 'error') && (
            <button className="scan-btn" onClick={onClose}>Close</button>
          )}
        </div>
      </div>
    </div>
  )
}

function SearchPage() {
  const [query, setQuery]         = useState('')
  const [language, setLanguage]   = useState('All')
  const [sortBy, setSortBy]       = useState('stars')
  const [allResults, setAllResults] = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [scanRepo, setScanRepo]   = useState(null) // repo being scanned — opens modal

  useEffect(() => { performSearch() }, [])

  useEffect(() => {
    const timer = setTimeout(() => performSearch(), 350)
    return () => clearTimeout(timer)
  }, [query])

  async function performSearch() {
    setLoading(true)
    setError(null)
    try {
      const data = await searchRepos(query)
      setAllResults(data)
    } catch (err) {
      setError(err.message || 'Search failed.')
      setAllResults([])
    } finally {
      setLoading(false)
    }
  }

  const languages = getLanguages(allResults)
  let filtered = filterByLanguage(allResults, language)
  if (sortBy === 'stars')   filtered = [...filtered].sort((a, b) => b.stars - a.stars)
  if (sortBy === 'updated') filtered = [...filtered].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
  if (sortBy === 'name')    filtered = [...filtered].sort((a, b) => a.name.localeCompare(b.name))

  const formatDate = (d) => new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })

  return (
    <div className="search-page">
      {scanRepo && <ScanModal repo={scanRepo} onClose={() => setScanRepo(null)} />}

      <div className="page-top">
        <h1>Search</h1>
        <p className="page-desc">Find tools and repositories across your organization</p>
      </div>

      <div className="search-bar-row">
        <div className="search-field">
          <svg className="search-field-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input type="text" placeholder="Search by name, description, or topic..." value={query} onChange={(e) => setQuery(e.target.value)} />
          {query && (
            <button className="search-field-clear" onClick={() => setQuery('')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          )}
        </div>
        <select value={language} onChange={(e) => setLanguage(e.target.value)} className="filter-ctl">
          {languages.map((l) => <option key={l} value={l}>{l === 'All' ? 'All languages' : l}</option>)}
        </select>
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} className="filter-ctl">
          <option value="stars">Most stars</option>
          <option value="updated">Recently updated</option>
          <option value="name">Name A–Z</option>
        </select>
      </div>

      {error && (
        <div className="search-error">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          {error}
          <button onClick={performSearch} className="retry-inline">Retry</button>
        </div>
      )}

      <div className="results-meta">
        {loading ? 'Searching...' : `${filtered.length} ${filtered.length === 1 ? 'result' : 'results'}`}
      </div>

      {!loading && !error && filtered.length > 0 && (
        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Language</th>
                <th>Topics</th>
                <th className="r">Stars</th>
                <th className="r">Forks</th>
                <th>Updated</th>
                <th>Scan</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((repo) => (
                <tr key={repo.id}>
                  <td>
                    <a href={repo.url} target="_blank" rel="noopener noreferrer" className="repo-link">{repo.name}</a>
                    <span className="repo-desc-line">{repo.description}</span>
                  </td>
                  <td><span className="lang-pill"><span className="lang-dot" style={{ background: LANG_COLORS[repo.language] || '#999' }}></span>{repo.language}</span></td>
                  <td><div className="topic-list">{repo.topics.slice(0, 3).map((t) => <span key={t} className="topic">{t}</span>)}</div></td>
                  <td className="r mono">{repo.stars}</td>
                  <td className="r mono">{repo.forks}</td>
                  <td className="date-cell">{formatDate(repo.updatedAt)}</td>
                  <td>
                    <button
                      className="scan-trigger-btn"
                      onClick={() => setScanRepo(repo)}
                      title={`Scan ${repo.name}`}
                    >
                      🔍 Scan
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && filtered.length === 0 && (
        <div className="empty-state">
          <p className="empty-title">No results found</p>
          <p>Try a different search term or adjust filters.</p>
        </div>
      )}
    </div>
  )
}

export default SearchPage
