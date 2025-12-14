import React, { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import api from '../services/api'
import { ArrowLeft, CheckCircle, XCircle, AlertCircle, Clock, Wrench } from 'lucide-react'
import './AuditDetail.css'

export default function AuditDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [audit, setAudit] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all') // all, passed, failed, skipped

  useEffect(() => {
    loadAuditDetail()
  }, [id])

  const loadAuditDetail = async () => {
    try {
      setLoading(true)
      const response = await api.get(`/reports/audits/${id}`)
      setAudit(response.data)
      setError(null)
    } catch (err) {
      console.error('Error loading audit detail:', err)
      setError(err.response?.data?.detail || 'Failed to load audit details')
    } finally {
      setLoading(false)
    }
  }

  const getFilteredResults = () => {
    if (!audit || !audit.results) return []
    const results = audit.results

    switch (filter) {
      case 'passed':
        return results.filter(r => r.exit_status === 0 || r.status === 'PASS')
      case 'failed':
        return results.filter(r => r.exit_status !== 0 && r.status !== 'PASS' && r.status !== 'SKIPPED')
      case 'skipped':
        return results.filter(r => r.status === 'SKIPPED')
      default:
        return results
    }
  }

  const getStatusIcon = (result) => {
    if (result.status === 'SKIPPED') {
      return <Clock size={16} className="icon-skipped" />
    }
    if (result.exit_status === 0 || result.status === 'PASS') {
      return <CheckCircle size={16} className="icon-passed" />
    }
    return <XCircle size={16} className="icon-failed" />
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading audit details...</p>
      </div>
    )
  }

  if (error || !audit) {
    return (
      <div className="audit-detail-page">
        <Link to="/audits" className="back-link">
          <ArrowLeft size={18} />
          Back to Audits
        </Link>
        <div className="error-banner">
          <AlertCircle size={20} />
          <span>{error || 'Audit not found'}</span>
        </div>
      </div>
    )
  }

  const filteredResults = getFilteredResults()
  const compliance = audit.compliance_score || 0
  const badgeClass = compliance >= 80 ? 'high' :
                    compliance >= 50 ? 'medium' : 'low'

  return (
    <div className="audit-detail-page">
      <Link to="/audits" className="back-link">
        <ArrowLeft size={18} />
        Back to Audits
      </Link>

      <div className="audit-header">
        <div>
          <h1>Audit Report Details</h1>
          <div className="audit-meta">
            <span className="meta-item">
              <strong>Host:</strong> {audit.host || 'Unknown'}
            </span>
            <span className="meta-item">
              <strong>OS:</strong> {audit.os_type || 'Unknown'}
            </span>
            <span className="meta-item">
              <strong>Date:</strong> {new Date(audit.created_at).toLocaleString()}
            </span>
          </div>
        </div>
        <div className="compliance-summary">
          <div className="compliance-score">
            <span className="compliance-label">Compliance Score</span>
            <span className={`compliance-value ${badgeClass}`}>
              {compliance.toFixed(1)}%
            </span>
          </div>
        </div>
      </div>

      <div className="filter-tabs">
        <button
          className={`filter-tab ${filter === 'all' ? 'active' : ''}`}
          onClick={() => setFilter('all')}
        >
          All ({audit.results?.length || 0})
        </button>
        <button
          className={`filter-tab ${filter === 'passed' ? 'active' : ''}`}
          onClick={() => setFilter('passed')}
        >
          Passed ({audit.results?.filter(r => r.exit_status === 0 || r.status === 'PASS').length || 0})
        </button>
        <button
          className={`filter-tab ${filter === 'failed' ? 'active' : ''}`}
          onClick={() => setFilter('failed')}
        >
          Failed ({audit.results?.filter(r => r.exit_status !== 0 && r.status !== 'PASS' && r.status !== 'SKIPPED').length || 0})
        </button>
        <button
          className={`filter-tab ${filter === 'skipped' ? 'active' : ''}`}
          onClick={() => setFilter('skipped')}
        >
          Skipped ({audit.results?.filter(r => r.status === 'SKIPPED').length || 0})
        </button>
      </div>

      <div className="results-container">
        {filteredResults.length === 0 ? (
          <div className="empty-state">No results found</div>
        ) : (
          filteredResults.map((result, index) => (
            <div key={index} className="result-card">
              <div className="result-header">
                <div className="result-title">
                  {getStatusIcon(result)}
                  <div>
                    <h3>{result.title || result.id || 'Unknown Rule'}</h3>
                    <p className="result-id">{result.id}</p>
                  </div>
                </div>
                <div className="result-status">
                  {result.exit_status === 0 || result.status === 'PASS' ? (
                    <span className="status-badge passed">PASSED</span>
                  ) : result.status === 'SKIPPED' ? (
                    <span className="status-badge skipped">SKIPPED</span>
                  ) : (
                    <span className="status-badge failed">FAILED</span>
                  )}
                </div>
              </div>
              
              {result.stdout && (
                <div className="result-output">
                  <strong>Output:</strong>
                  <pre>{result.stdout}</pre>
                </div>
              )}
              
              {result.stderr && (
                <div className="result-output error">
                  <strong>Error:</strong>
                  <pre>{result.stderr}</pre>
                </div>
              )}
              
              {result.duration_ms && (
                <div className="result-meta">
                  <span>Duration: {result.duration_ms}ms</span>
                  {result.exit_status !== undefined && (
                    <span>Exit Code: {result.exit_status}</span>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

