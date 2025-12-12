import React, { useState, useEffect } from 'react'
import api from '../services/api'
import { Server, RefreshCw, AlertCircle } from 'lucide-react'
import './Hosts.css'

export default function Hosts() {
  const [hosts, setHosts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadHosts()
  }, [])

  const loadHosts = async () => {
    try {
      setLoading(true)
      const response = await api.get('/reports/hosts')
      setHosts(response.data.hosts || [])
      setError(null)
    } catch (err) {
      console.error('Error loading hosts:', err)
      setError(err.response?.data?.detail || 'Failed to load hosts')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading hosts...</p>
      </div>
    )
  }

  return (
    <div className="hosts-page">
      <div className="page-header">
        <h1>Hosts</h1>
        <button onClick={loadHosts} className="refresh-btn">
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

      {hosts.length === 0 ? (
        <div className="empty-state">
          <Server size={48} />
          <h2>No hosts found</h2>
          <p>Run an audit to start monitoring hosts</p>
        </div>
      ) : (
        <div className="hosts-table-container">
          <table className="hosts-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>OS Type</th>
                <th>Compliance Score</th>
                <th>Total Rules</th>
                <th>Passed Rules</th>
                <th>Last Audit</th>
                <th>Audit Count</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => {
                const compliance = host.compliance_score || 0
                const badgeClass = compliance >= 80 ? 'high' :
                                  compliance >= 50 ? 'medium' : 'low'
                
                return (
                  <tr key={host.id || host.host}>
                    <td>
                      <div className="host-cell">
                        <Server size={16} />
                        <strong>{host.host || 'Unknown'}</strong>
                      </div>
                    </td>
                    <td>
                      <span className="os-badge">{host.os_type || 'Unknown'}</span>
                    </td>
                    <td>
                      <div className="compliance-cell">
                        <span className={`compliance-badge ${badgeClass}`}>
                          {compliance.toFixed(1)}%
                        </span>
                        <div className="compliance-bar">
                          <div 
                            className={`compliance-fill ${badgeClass}`}
                            style={{ width: `${compliance}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td>{host.total_rules || 0}</td>
                    <td>
                      <span className="passed-rules">
                        {host.passed_rules || 0}
                      </span>
                    </td>
                    <td>
                      {host.latest_audit_time 
                        ? new Date(host.latest_audit_time).toLocaleString()
                        : 'Never'
                      }
                    </td>
                    <td>{host.audit_count || 0}</td>
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

