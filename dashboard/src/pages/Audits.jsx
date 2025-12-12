import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import api from '../services/api'
import { FileCheck, RefreshCw, AlertCircle, Eye } from 'lucide-react'
import './Audits.css'

export default function Audits() {
  const [audits, setAudits] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadAudits()
  }, [])

  const loadAudits = async () => {
    try {
      setLoading(true)
      const response = await api.get('/reports/audits?limit=50')
      setAudits(response.data.audits || [])
      setError(null)
    } catch (err) {
      console.error('Error loading audits:', err)
      setError(err.response?.data?.detail || 'Failed to load audits')
    } finally {
      setLoading(false)
    }
  }

  const getStatusCounts = (audit) => {
    const results = audit.results || []
    const passed = results.filter(r => r.exit_status === 0 || r.status === 'PASS').length
    const failed = results.filter(r => r.exit_status !== 0 && r.status !== 'PASS' && r.status !== 'SKIPPED').length
    const skipped = results.filter(r => r.status === 'SKIPPED').length
    return { passed, failed, skipped, total: results.length }
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading audits...</p>
      </div>
    )
  }

  return (
    <div className="audits-page">
      <div className="page-header">
        <h1>Audit Reports</h1>
        <button onClick={loadAudits} className="refresh-btn">
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="error-banner">
          <AlertCircle size={20} />
          <span>{error}</span>
        </div>
      )}

      {audits.length === 0 ? (
        <div className="empty-state">
          <FileCheck size={48} />
          <h2>No audit reports found</h2>
          <p>Run an audit to generate reports</p>
        </div>
      ) : (
        <div className="audits-table-container">
          <table className="audits-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>OS Type</th>
                <th>Compliance</th>
                <th>Status</th>
                <th>Date</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {audits.map((audit) => {
                const compliance = audit.compliance_score || 0
                const badgeClass = compliance >= 80 ? 'high' :
                                  compliance >= 50 ? 'medium' : 'low'
                const counts = getStatusCounts(audit)
                
                return (
                  <tr key={audit.id}>
                    <td>
                      <div className="host-cell">
                        <strong>{audit.host || 'Unknown'}</strong>
                      </div>
                    </td>
                    <td>
                      <span className="os-badge">{audit.os_type || 'Unknown'}</span>
                    </td>
                    <td>
                      <span className={`compliance-badge ${badgeClass}`}>
                        {compliance.toFixed(1)}%
                      </span>
                    </td>
                    <td>
                      <div className="status-cell">
                        <span className="status-badge passed">{counts.passed} Passed</span>
                        <span className="status-badge failed">{counts.failed} Failed</span>
                        {counts.skipped > 0 && (
                          <span className="status-badge skipped">{counts.skipped} Skipped</span>
                        )}
                      </div>
                    </td>
                    <td>{new Date(audit.created_at).toLocaleString()}</td>
                    <td>
                      <Link to={`/audits/${audit.id}`} className="view-btn">
                        <Eye size={16} />
                        View Details
                      </Link>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

