import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { Wrench, RefreshCw, AlertCircle, CheckCircle, XCircle, Plus, RotateCcw } from 'lucide-react'
import './Remediations.css'

export default function Remediations() {
  const navigate = useNavigate()
  const { userRole } = useAuth()
  const [remediations, setRemediations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    console.log('Remediations page - userRole:', userRole, 'isAdmin:', userRole === 'admin', 'type:', typeof userRole)
    loadRemediations()
  }, [userRole])

  const loadRemediations = async () => {
    try {
      setLoading(true)
      const response = await api.get('/reports/remediations?limit=50')
      setRemediations(response.data.remediations || [])
      setError(null)
    } catch (err) {
      console.error('Error loading remediations:', err)
      setError(err.response?.data?.detail || 'Failed to load remediations')
    } finally {
      setLoading(false)
    }
  }

  const getStatusIcon = (status) => {
    if (status === 'SUCCESS') {
      return <CheckCircle size={16} className="icon-success" />
    }
    return <XCircle size={16} className="icon-partial" />
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading remediations...</p>
      </div>
    )
  }

  return (
    <div className="remediations-page">
      <div className="page-header">
        <h1>Remediations</h1>
        <div className="header-actions">
          {(() => {
            const cleanRole = userRole ? String(userRole).trim().toLowerCase() : ''
            const isAdmin = cleanRole === 'admin'
            console.log('Remediations render - userRole:', userRole, 'cleanRole:', cleanRole, 'isAdmin:', isAdmin)
            if (cleanRole !== 'admin') {
              return null
            }
            return (
              <>
                <button onClick={() => navigate('/remediate/new')} className="btn-new-remediation">
                  <Plus size={18} />
                  New Remediation
                </button>
                <button onClick={() => navigate('/rollback')} className="btn-rollback">
                  <RotateCcw size={18} />
                  Rollback
                </button>
              </>
            )
          })()}
          <button onClick={loadRemediations} className="refresh-btn">
            <RefreshCw size={18} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <AlertCircle size={20} />
          <span>{error}</span>
        </div>
      )}

      {remediations.length === 0 ? (
        <div className="empty-state">
          <Wrench size={48} />
          <h2>No remediation logs found</h2>
          <p>Remediation actions will appear here</p>
        </div>
      ) : (
        <div className="remediations-container">
          {remediations.map((remediation) => (
            <div key={remediation.id} className="remediation-card">
              <div className="remediation-header">
                <div className="remediation-title">
                  {getStatusIcon(remediation.status)}
                  <div>
                    <h3>
                      {remediation.rule_id || remediation.script_used || 'Remediation'}
                    </h3>
                    <p className="remediation-meta">
                      <span>{remediation.host || 'Unknown Host'}</span>
                      {remediation.os_type && (
                        <>
                          <span>•</span>
                          <span>{remediation.os_type}</span>
                        </>
                      )}
                      {remediation.created_at && (
                        <>
                          <span>•</span>
                          <span>{new Date(remediation.created_at).toLocaleString()}</span>
                        </>
                      )}
                    </p>
                  </div>
                </div>
                <div className="remediation-status">
                  <span className={`status-badge ${remediation.status?.toLowerCase()}`}>
                    {remediation.status || 'UNKNOWN'}
                  </span>
                </div>
              </div>

              <div className="remediation-details">
                {remediation.backup_id && (
                  <div className="detail-item">
                    <strong>Backup ID:</strong> {remediation.backup_id}
                  </div>
                )}
                {remediation.exit_code !== undefined && (
                  <div className="detail-item">
                    <strong>Exit Code:</strong> {remediation.exit_code}
                  </div>
                )}
                {remediation.verification_passed !== undefined && (
                  <div className="detail-item">
                    <strong>Verification:</strong>{' '}
                    {remediation.verification_passed ? (
                      <span className="verification-passed">✓ Passed</span>
                    ) : (
                      <span className="verification-failed">✗ Failed</span>
                    )}
                  </div>
                )}
              {remediation.rollback_status && remediation.rollback_status === 'AVAILABLE' && remediation.backup_id && (
                <div className="detail-item">
                  <strong>Rule Backup:</strong>{' '}
                  <span className="rollback-available">Available</span>
                  {userRole && String(userRole).trim().toLowerCase() === 'admin' && (
                    <button
                      onClick={() => {
                        if (remediation.status === 'SUCCESS' && remediation.verification_passed === true) {
                          if (window.confirm(
                            `⚠️ Rollback Warning\n\n` +
                            `This remediation was successful. Rolling back will restore the system to its state before this remediation was applied.\n\n` +
                            `Before remediation: System was in its previous state\n` +
                            `After remediation: Rule ${remediation.rule_id || 'N/A'} is now PASS\n` +
                            `Rollback will restore: System back to the state before remediation\n\n` +
                            `Do you want to continue?`
                          )) {
                            navigate('/rollback', {
                              state: {
                                host: remediation.host,
                                osType: remediation.os_type || remediation.os || remediation.client_type === 'linux' ? 'linux' : 'windows',
                                selectedBackup: remediation.backup_id,
                                remediationId: remediation.remediation_id || remediation._id,
                                ruleId: remediation.rule_id,
                                backupType: 'rules'
                              }
                            })
                          }
                        } else {
                          navigate('/rollback', {
                            state: {
                              host: remediation.host,
                              osType: remediation.os_type || remediation.os || remediation.client_type === 'linux' ? 'linux' : 'windows',
                              selectedBackup: remediation.backup_id,
                              remediationId: remediation.remediation_id || remediation._id,
                              ruleId: remediation.rule_id,
                              backupType: 'rules'
                            }
                          })
                        }
                      }}
                      className="btn-rollback-small"
                      title="Rollback rule"
                    >
                      <RotateCcw size={14} />
                      Rollback Rule
                    </button>
                  )}
                </div>
              )}
              </div>

              {remediation.output && (
                <div className="remediation-output">
                  <strong>Output:</strong>
                  <pre>{remediation.output.substring(0, 500)}{remediation.output.length > 500 ? '...' : ''}</pre>
                </div>
              )}

              {remediation.error && (
                <div className="remediation-output error">
                  <strong>Error:</strong>
                  <pre>{remediation.error.substring(0, 500)}{remediation.error.length > 500 ? '...' : ''}</pre>
                </div>
              )}

              {remediation.message && (
                <div className="remediation-message">
                  {remediation.message}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

