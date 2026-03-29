import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getScan, pollScan, SEVERITY_CONFIG, RISK_CONFIG } from '../services/scans'
import './ScanResultsPage.css'

function ScanResultsPage() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedFinding, setExpandedFinding] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('All')

  useEffect(() => {
    loadScan()
  }, [scanId])

  async function loadScan() {
    setLoading(true)
    setError(null)

    try {
      const { scan: scanData } = await getScan(scanId)
      setScan(scanData)

      // If the scan is still running, start polling
      if (scanData.status === 'scanning' || scanData.status === 'pending') {
        pollScan(scanId, (updated) => setScan(updated))
      }
    } catch (err) {
      setError(err.message || 'Failed to load scan.')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="page-state">
        <div className="spinner"></div>
        <p>Loading scan...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="page-state">
        <div className="error-box">
          <strong>Error</strong>
          <p>{error}</p>
          <button onClick={loadScan} className="retry-btn">Retry</button>
        </div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="page-state">
        <p>Scan not found.</p>
        <Link to="/search" className="back-link">Back to Search</Link>
      </div>
    )
  }

  const isScanning = scan.status === 'scanning' || scan.status === 'pending'
  const isError = scan.status === 'error'
  const isComplete = scan.status === 'complete'

  const allFindings = scan.findings || []
  const riskConfig = RISK_CONFIG[scan.risk_level] || RISK_CONFIG.unknown

  // Separate true positives from false positives
  const findings = allFindings.filter((f) => !f.falsePositive)
  const falsePositives = allFindings.filter((f) => f.falsePositive)

  // Count findings by severity (true positives only)
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  findings.forEach((f) => {
    const sev = (f.severity || '').toLowerCase()
    if (severityCounts[sev] !== undefined) severityCounts[sev]++
  })

  // Filter findings
  const filteredFindings = severityFilter === 'All'
    ? findings
    : findings.filter((f) => (f.severity || '').toLowerCase() === severityFilter.toLowerCase())

  const formatDate = (dateString) => {
    if (!dateString) return '—'
    return new Date(dateString).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: 'numeric', minute: '2-digit',
    })
  }

  return (
    <div className="scan-results-page">
      {/* Header */}
      <div className="scan-header">
        <Link to="/search" className="back-link">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="15 18 9 12 15 6"/>
          </svg>
          Back to Search
        </Link>

        <div className="scan-title-row">
          <h1>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            {scan.repo_name}
          </h1>
          {isComplete && (
            <span className="risk-badge" style={{ background: riskConfig.bg, color: riskConfig.color }}>
              {riskConfig.label}
            </span>
          )}
        </div>

        <div className="scan-meta">
          <span>Scan #{scan.id}</span>
          <span className="meta-sep">·</span>
          <span>Started {formatDate(scan.started_at)}</span>
          {scan.completed_at && (
            <>
              <span className="meta-sep">·</span>
              <span>Completed {formatDate(scan.completed_at)}</span>
            </>
          )}
          {scan.file_count > 0 && (
            <>
              <span className="meta-sep">·</span>
              <span>{scan.file_count} files analyzed</span>
            </>
          )}
          {scan.requested_by_name && (
            <>
              <span className="meta-sep">·</span>
              <span>by {scan.requested_by_name}</span>
            </>
          )}
        </div>
      </div>

      {/* Scanning state */}
      {isScanning && (
        <div className="scan-progress-panel">
          <div className="scan-progress-content">
            <div className="scan-progress-spinner"></div>
            <div>
              <strong>Scanning repository...</strong>
              <p>Fetching source files from GitHub, running security analysis, and generating fix recommendations. This usually takes 15–30 seconds.</p>
            </div>
          </div>
        </div>
      )}

      {/* Error state */}
      {isError && (
        <div className="scan-error-panel">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
          </svg>
          <div>
            <strong>Scan failed</strong>
            <p>{scan.summary || 'An unknown error occurred.'}</p>
          </div>
          <button onClick={loadScan} className="retry-btn">Retry</button>
        </div>
      )}

      {/* Results */}
      {isComplete && (
        <>
          {/* Summary */}
          {scan.summary && (
            <div className="scan-summary-panel">
              <h3>Executive Summary</h3>
              <p>{scan.summary}</p>
            </div>
          )}

          {/* Severity breakdown */}
          <div className="severity-bar-row">
            {Object.entries(severityCounts).map(([sev, count]) => {
              const config = SEVERITY_CONFIG[sev]
              if (!config) return null
              return (
                <button
                  key={sev}
                  className={`severity-chip ${severityFilter.toLowerCase() === sev ? 'active' : ''}`}
                  style={{
                    '--chip-color': config.color,
                    '--chip-bg': config.bg,
                  }}
                  onClick={() => setSeverityFilter(severityFilter === sev ? 'All' : sev)}
                >
                  <span className="severity-dot" style={{ background: config.color }}></span>
                  {config.label}
                  <span className="severity-count">{count}</span>
                </button>
              )
            })}
            {severityFilter !== 'All' && (
              <button className="clear-filter" onClick={() => setSeverityFilter('All')}>
                Clear filter
              </button>
            )}
          </div>

          {/* Findings list */}
          {filteredFindings.length > 0 ? (
            <div className="findings-list">
              {filteredFindings.map((finding, idx) => {
                const sevConfig = SEVERITY_CONFIG[(finding.severity || '').toLowerCase()] || SEVERITY_CONFIG.info
                const isExpanded = expandedFinding === idx

                return (
                  <div key={idx} className={`finding-card ${isExpanded ? 'expanded' : ''}`}>
                    <button
                      className="finding-header"
                      onClick={() => setExpandedFinding(isExpanded ? null : idx)}
                    >
                      <span className="finding-severity" style={{ background: sevConfig.bg, color: sevConfig.color }}>
                        {sevConfig.label}
                      </span>
                      <span className="finding-title">{finding.title}</span>
                      {finding.file && (
                        <span className="finding-file">
                          {finding.file}{finding.line ? `:${finding.line}` : ''}
                        </span>
                      )}
                      <svg className={`finding-chevron ${isExpanded ? 'open' : ''}`} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="6 9 12 15 18 9"/>
                      </svg>
                    </button>

                    {isExpanded && (
                      <div className="finding-details">
                        <div className="finding-section">
                          <h4>Description</h4>
                          <p>{finding.description}</p>
                        </div>
                        {finding.recommendation && (
                          <div className="finding-section fix-recommendation">
                            <h4>
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/>
                              </svg>
                              Suggested Fix
                            </h4>
                            <pre className="fix-code-block">{finding.recommendation}</pre>
                          </div>
                        )}
                        {finding.cwe && (
                          <div className="finding-cwe">
                            <a
                              href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {finding.cwe}
                            </a>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="no-findings">
              {findings.length === 0 ? (
                <>
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                  </svg>
                  <p className="no-findings-title">No vulnerabilities found</p>
                  <p>The security scanner did not detect any issues in the scanned files.</p>
                </>
              ) : (
                <p>No findings match the selected filter.</p>
              )}
            </div>
          )}

          {/* False positives dismissed by Claude */}
          {falsePositives.length > 0 && (
            <div className="false-positives-note">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
              </svg>
              {falsePositives.length} finding{falsePositives.length > 1 ? 's' : ''} dismissed as false positive{falsePositives.length > 1 ? 's' : ''} by Claude AI review.
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default ScanResultsPage
