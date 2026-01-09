import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { Wrench, RefreshCw, AlertCircle, CheckCircle, XCircle, Plus, RotateCcw, Trash2, Settings, ChevronDown, ChevronUp } from 'lucide-react'
import './Remediations.css'

export default function Remediations() {
  const navigate = useNavigate()
  const { userRole } = useAuth()
  const [remediations, setRemediations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [showClearDataModal, setShowClearDataModal] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [expandedIds, setExpandedIds] = useState(new Set())

  useEffect(() => {
    console.log('Remediations page - userRole:', userRole, 'isAdmin:', userRole === 'admin', 'type:', typeof userRole)
    loadRemediations()
  }, [userRole])

  const loadRemediations = async () => {
    try {
      setLoading(true)
      setError(null)
      console.log('Loading remediations...')
      const response = await api.get('/reports/remediations?limit=50')
      console.log('API Response:', response)
      console.log('Response data:', response.data)
      const remediationsList = response.data?.remediations || response.data || []
      console.log('Remediations list:', remediationsList, 'Type:', typeof remediationsList, 'Is Array:', Array.isArray(remediationsList))
      setRemediations(Array.isArray(remediationsList) ? remediationsList : [])
    } catch (err) {
      console.error('Error loading remediations:', err)
      console.error('Error response:', err.response)
      console.error('Error message:', err.message)
      setError(err.response?.data?.detail || err.message || 'Failed to load remediations')
      setRemediations([]) // Set empty array on error
    } finally {
      setLoading(false)
    }
  }

  const formatVietnamTime = (value) => {
    try {
      return new Date(value).toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' })
    } catch (e) {
      console.warn('Invalid remediation date:', value, e)
      return value || ''
    }
  }

  const getStatusIcon = (status) => {
    if (status === 'SUCCESS') {
      return <CheckCircle size={16} className="icon-success" />
    }
    return <XCircle size={16} className="icon-partial" />
  }

  const handleSelectAll = () => {
    if (selectedIds.size === remediations.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(remediations.map(r => r.remediation_id || r._id || r.id)))
    }
  }

  const handleToggleSelect = (id) => {
    const newSelected = new Set(selectedIds)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedIds(newSelected)
  }

  const handleToggleExpand = (id) => {
    const newExpanded = new Set(expandedIds)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedIds(newExpanded)
  }

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return
    
    const confirmMessage = `Are you sure you want to delete ${selectedIds.size} remediation(s)? This action cannot be undone.`
    if (!window.confirm(confirmMessage)) return

    try {
      setDeleting(true)
      const idsArray = Array.from(selectedIds)
      await api.post('/remediations/bulk-delete', { ids: idsArray })
      alert(`Successfully deleted ${idsArray.length} remediation(s)`)
      setSelectedIds(new Set())
      loadRemediations()
    } catch (err) {
      console.error('Error deleting remediations:', err)
      const errorMessage = err.response?.data?.detail || err.response?.data?.message || err.message || 'Failed to delete remediations'
      alert(typeof errorMessage === 'string' ? errorMessage : JSON.stringify(errorMessage))
    } finally {
      setDeleting(false)
    }
  }

  const handleClearData = async () => {
    const confirmMessage = `⚠️ WARNING: This will delete ALL data from the database:\n\n` +
      `- All audit reports\n` +
      `- All remediation logs\n` +
      `- All backups (rule backups and system backups)\n` +
      `- All backup schedules\n\n` +
      `Users and API keys will be preserved.\n\n` +
      `This action CANNOT be undone. Are you absolutely sure?`
    
    if (!window.confirm(confirmMessage)) return

    const doubleConfirm = window.prompt('Type "DELETE ALL" to confirm:')
    if (doubleConfirm !== 'DELETE ALL') {
      alert('Clear data cancelled')
      return
    }

    try {
      setDeleting(true)
      await api.post('/database/clear-data')
      alert('All data has been cleared successfully')
      setShowClearDataModal(false)
      loadRemediations()
    } catch (err) {
      console.error('Error clearing data:', err)
      const errorMessage = err.response?.data?.detail || err.response?.data?.message || err.message || 'Failed to clear data'
      alert(typeof errorMessage === 'string' ? errorMessage : JSON.stringify(errorMessage))
    } finally {
      setDeleting(false)
    }
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
                {selectedIds.size > 0 && (
                  <button 
                    onClick={handleBulkDelete} 
                    className="btn-delete-selected"
                    disabled={deleting}
                  >
                    <Trash2 size={18} />
                    Delete Selected ({selectedIds.size})
                  </button>
                )}
                <button 
                  onClick={() => setShowClearDataModal(true)} 
                  className="btn-clear-data"
                >
                  <Settings size={18} />
                  Clear Data
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
        <div className="error-banner" style={{ padding: '20px', background: '#fee', border: '2px solid red', margin: '20px', borderRadius: '8px' }}>
          <AlertCircle size={20} />
          <span style={{ marginLeft: '10px', fontWeight: 'bold' }}>Error: {error}</span>
          <button onClick={loadRemediations} style={{ marginLeft: '20px', padding: '5px 10px', cursor: 'pointer' }}>
            Retry
          </button>
        </div>
      )}
      
      {!error && remediations.length === 0 && !loading && (
        <div style={{ padding: '40px', textAlign: 'center', color: '#666' }}>
          <p>No remediations found.</p>
          <button onClick={loadRemediations} style={{ marginTop: '10px', padding: '8px 16px' }}>
            Refresh
          </button>
        </div>
      )}

      {remediations.length === 0 ? (
        <div className="empty-state">
          <Wrench size={48} />
          <h2>No remediation logs found</h2>
          <p>Remediation actions will appear here</p>
        </div>
      ) : (
        <>
          <div className="bulk-actions">
            <label className="select-all-checkbox">
              <input
                type="checkbox"
                checked={selectedIds.size === remediations.length && remediations.length > 0}
                onChange={handleSelectAll}
              />
              <span>Select All</span>
            </label>
            {selectedIds.size > 0 && (
              <span className="selected-count">
                {selectedIds.size} selected
              </span>
            )}
          </div>
          <div className="remediations-container">
            {remediations.map((remediation, index) => {
              try {
                const remediationId = remediation?.remediation_id || remediation?._id || remediation?.id || `remediation-${index}`
                if (!remediationId) {
                  console.warn('Remediation without ID:', remediation)
                  return null
                }
                
                const isWindows = remediation?.os_type && (
                  remediation.os_type.toLowerCase().includes('windows') || 
                  remediation.os_type.toLowerCase().includes('win')
                )
                const isExpanded = expandedIds.has(remediationId)
                // Fallback: check cả script_output/script_error
                const hasDetails = remediation?.output || remediation?.error || 
                                   remediation?.script_output || remediation?.script_error || 
                                   remediation?.verification_passed !== undefined
                
                return (
                <div key={remediationId} className="remediation-card">
                {userRole && String(userRole).trim().toLowerCase() === 'admin' && (
                  <div className="remediation-checkbox">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(remediationId)}
                      onChange={() => handleToggleSelect(remediationId)}
                    />
                  </div>
                )}
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
                          <span>{formatVietnamTime(remediation.created_at)}</span>
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

              {/* Summary section - always visible */}
              <div className="remediation-details">
                {remediation?.backup_id && (
                  <div className="detail-item">
                    <strong>Backup ID:</strong> {remediation.backup_id}
                  </div>
                )}
                {remediation?.exit_code !== undefined && (
                  <div className="detail-item">
                    <strong>Exit Code:</strong> {remediation.exit_code}
                  </div>
                )}
                {/* Linux: Show verification in summary, Windows: Show in details */}
                {!isWindows && remediation?.verification_passed !== undefined && (
                  <div className="detail-item">
                    <strong>Verification:</strong>{' '}
                    {remediation.verification_passed ? (
                      <span className="verification-passed">✓ Passed</span>
                    ) : (
                      <span className="verification-failed">✗ Failed</span>
                    )}
                  </div>
                )}
              {remediation?.rollback_status && remediation.rollback_status === 'AVAILABLE' && remediation?.backup_id && (
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

              {/* Windows: Collapsible details button - only show if there are details */}
              {isWindows && hasDetails && (
                <div className="remediation-details-toggle">
                  <button
                    onClick={() => handleToggleExpand(remediationId)}
                    className="btn-toggle-details"
                  >
                    {isExpanded ? (
                      <>
                        <ChevronUp size={16} />
                        Hide Details
                      </>
                    ) : (
                      <>
                        <ChevronDown size={16} />
                        View Details
                      </>
                    )}
                  </button>
                </div>
              )}

              {/* Details section - Windows: only when expanded, Linux: always show */}
              {(!isWindows || isExpanded) && (
                <>
                  {/* Windows: Show verification in details section */}
                  {isWindows && remediation.verification_passed !== undefined && (
                    <div className="remediation-details">
                    <div className="detail-item">
                      <strong>Verification:</strong>{' '}
                      {remediation.verification_passed ? (
                        <span className="verification-passed">✓ Passed</span>
                      ) : (
                        <span className="verification-failed">✗ Failed</span>
                      )}
                      </div>
                    </div>
                  )}

                  {/* Output and Error - only in details section */}
                  {/* Fallback: đọc từ script_output nếu output không có */}
                  {(remediation.output || remediation.script_output) && (
                    <div className="remediation-output">
                      <strong>Output:</strong>
                      <pre>{remediation.output || remediation.script_output || ''}</pre>
                    </div>
                  )}

                  {/* Fallback: đọc từ script_error nếu error không có */}
                  {(remediation.error || remediation.script_error) && (
                    <div className="remediation-output error">
                      <strong>Error:</strong>
                      <pre>{remediation.error || remediation.script_error || ''}</pre>
                    </div>
                  )}
                </>
              )}

              {remediation?.message && (
                <div className="remediation-message">
                  {remediation.message}
                </div>
              )}
            </div>
                )
              } catch (err) {
                console.error('Error rendering remediation card:', err, remediation)
                return (
                  <div key={`error-${index}`} className="remediation-card" style={{ border: '2px solid red' }}>
                    <div className="remediation-header">
                      <div className="remediation-title">
                        <AlertCircle size={16} className="icon-partial" />
                        <div>
                          <h3>Error rendering remediation</h3>
                          <p className="remediation-meta">
                            <span>Error: {err.message}</span>
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )
              }
            })}
          </div>
        </>
      )}

      {/* Clear Data Modal */}
      {showClearDataModal && (
        <div className="modal-overlay" onClick={() => setShowClearDataModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Clear All Data</h2>
            <div className="clear-data-warning">
              <AlertCircle size={24} />
              <p><strong>Warning:</strong> This will permanently delete:</p>
              <ul>
                <li>All audit reports</li>
                <li>All remediation logs</li>
                <li>All backups (rule backups and system backups)</li>
                <li>All backup schedules</li>
              </ul>
              <p><strong>Users and API keys will be preserved.</strong></p>
            </div>
            <div className="modal-actions">
              <button 
                type="button" 
                onClick={() => setShowClearDataModal(false)} 
                className="btn-secondary"
              >
                Cancel
              </button>
              <button 
                onClick={handleClearData} 
                disabled={deleting}
                className="btn-danger"
              >
                {deleting ? 'Clearing...' : 'Clear All Data'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

