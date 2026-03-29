import { useState, useEffect } from 'react'
import { searchRepos, filterByLanguage, getLanguages } from '../services/github'
import './SearchPage.css'

const LANG_COLORS = {
  JavaScript: '#f0db4f',
  TypeScript: '#3178c6',
  Python: '#3572A5',
  Go: '#00ADD8',
  Rust: '#dea584',
  Swift: '#F05138',
  Dockerfile: '#384d54',
  HCL: '#5c4ee5',
}

function SearchPage() {
  const [query, setQuery] = useState('')
  const [language, setLanguage] = useState('All')
  const [sortBy, setSortBy] = useState('stars')
  const [allResults, setAllResults] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    performSearch()
  }, [])

  useEffect(() => {
    const timer = setTimeout(() => {
      performSearch()
    }, 350)
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

  if (sortBy === 'stars') {
    filtered = [...filtered].sort((a, b) => b.stars - a.stars)
  } else if (sortBy === 'updated') {
    filtered = [...filtered].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
  } else if (sortBy === 'name') {
    filtered = [...filtered].sort((a, b) => a.name.localeCompare(b.name))
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
    })
  }

  return (
    <div className="search-page">
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
          {languages.map((l) => (
            <option key={l} value={l}>{l === 'All' ? 'All languages' : l}</option>
          ))}
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
                  <td><div className="topic-list">{repo.topics.slice(0, 3).map((t) => (<span key={t} className="topic">{t}</span>))}</div></td>
                  <td className="r mono">{repo.stars}</td>
                  <td className="r mono">{repo.forks}</td>
                  <td className="date-cell">{formatDate(repo.updatedAt)}</td>
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
