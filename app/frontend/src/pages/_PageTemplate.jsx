// ============================================================
//  ToolVault — Page Template
// ============================================================
//
//  COPY THIS FILE to create a new page. For example:
//    pages/DefectDojoPage.jsx
//
//  Then:
//    1. Rename "TemplatePage" to your page name
//    2. Update the imports to use your service file
//    3. Customize the columns and display fields
//    4. Create a CSS file (e.g. DefectDojoPage.css)
//    5. Add the route in App.jsx:
//         import DefectDojoPage from './pages/DefectDojoPage'
//         <Route path="/defectdojo" element={isLoggedIn ? <DefectDojoPage /> : <Navigate to="/login" />} />
//    6. Add a nav link in components/Navbar.jsx
//
// ============================================================

import { useState, useEffect } from 'react'
// TODO: Replace with your actual service imports
// import { getAllItems, searchItems, filterItems, getUniqueValues } from '../services/defectdojo'
// import './DefectDojoPage.css'

function TemplatePage() {
  const [items, setItems] = useState([])
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    setLoading(true)
    setError(null)
    try {
      // TODO: Replace with your actual API call
      // const data = await getAllItems()
      const data = [] // placeholder
      setItems(data)
    } catch (err) {
      setError(err.message || 'Failed to load data.')
    } finally {
      setLoading(false)
    }
  }

  // --- Loading state ---
  if (loading) {
    return (
      <div className="page-state">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    )
  }

  // --- Error state ---
  if (error) {
    return (
      <div className="page-state">
        <div className="error-box">
          <strong>Error loading data</strong>
          <p>{error}</p>
          <button onClick={loadData} className="retry-btn">Retry</button>
        </div>
      </div>
    )
  }

  // --- Main content ---
  return (
    <div className="template-page">
      <div className="page-top">
        <h1>Page Title</h1>
        <p className="page-desc">Brief description of what this page shows</p>
      </div>

      {/* Search bar (optional) */}
      <div className="search-bar-row">
        <input
          type="text"
          placeholder="Search..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {/* Results table */}
      {items.length > 0 ? (
        <div className="panel">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>Severity</th>
                {/* Add more columns as needed */}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td>{item.title}</td>
                  <td>{item.status}</td>
                  <td>{item.severity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="page-state">
          <p>No items found.</p>
        </div>
      )}
    </div>
  )
}

export default TemplatePage
