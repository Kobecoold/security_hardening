import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { RotateCcw, Loader, AlertCircle, CheckCircle, Clock, Server } from 'lucide-react'
import './Rollback.css'

export default function Rollback() {
  const navigate = useNavigate()
  const { userRole } = useAuth()
  
  useEffect(() => {
    if (userRole !== 'admin') {
      navigate('/remediations')
    }
  }, [userRole, navigate])
  const [host, setHost] = useState('')
  const [osType, setOsType] = useState('linux')
  const [loading, setLoading] = useState(false)
  const [loadingBackups, setLoadingBackups] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  const [backups, setBackups] = useState([])
  const [selectedBackup, setSelectedBackup] = useState('')
  const [remediationInfo, setRemediationInfo] = useState(null)

  // Connection form
  const [formData, setFormData] = useState({
    username: '',
    key_path: '',
    password: '',
    sudo_password: ''
  })

  // Get state from navigation (when coming from remediation)
  useEffect(() => {
    const locationState = window.history.state?.usr || {}
    if (locationState.host) {
      setHost(locationState.host)
    }
    if (locationState.osType) {
      setOsType(locationState.osType)
    }
    if (locationState.selectedBackup) {
      setSelectedBackup(locationState.selectedBackup)
      setRemediationInfo({
        remediationId: locationState.remediationId,
        ruleId: locationState.ruleId
      })
    }
  }, [])

  useEffect(() => {
    if (host && osType) {
      loadBackups()
    }
  }, [host, osType])

  const loadBackups = async () => {
    if (!host) return

    try {
      setLoadingBackups(true)
      const endpoint = osType === 'linux' || osType.startsWith('ubuntu') || osType.startsWith('debian')
        ? `/backups/linux?host=${host}`
        : `/backups/windows?host=${host}`
      
      const response = await api.get(endpoint)
      setBackups(response.data.backups || [])
      
      if (response.data.backups.length > 0) {
        // If we have a selectedBackup from navigation state, keep it
        // Otherwise, auto-select latest backup
        if (!selectedBackup) {
          setSelectedBackup(response.data.backups[0].backup_id || response.data.backups[0]._id)
        } else {
          // Verify the selected backup exists in the list
          const backupExists = response.data.backups.some(b => 
            (b.backup_id || b._id) === selectedBackup
          )
          if (!backupExists) {
            // If selected backup not found, select latest
            setSelectedBackup(response.data.backups[0].backup_id || response.data.backups[0]._id)
          }
        }
      }
    } catch (err) {
      console.error('Error loading backups:', err)
      setError('Failed to load backups: ' + (err.response?.data?.detail || err.message))
    } finally {
      setLoadingBackups(false)
    }
  }

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    if (name === 'host') {
      setHost(value)
      setBackups([])
      setSelectedBackup('')
    } else if (name === 'osType') {
      setOsType(value)
      setBackups([])
      setSelectedBackup('')
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: type === 'checkbox' ? checked : value
      }))
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)
    setLoading(true)

    try {
      if (osType === 'linux' || osType.startsWith('ubuntu') || osType.startsWith('debian')) {
        // Linux rollback
        const formDataToSend = new FormData()
        formDataToSend.append('Host', host)
        formDataToSend.append('Username', formData.username)
        if (formData.key_path) formDataToSend.append('Key_path', formData.key_path)
        if (formData.password) formDataToSend.append('Password', formData.password)
        if (formData.sudo_password) formDataToSend.append('Sudo_password', formData.sudo_password)
        if (selectedBackup) formDataToSend.append('backup_id', selectedBackup)

        const response = await api.post('/rollback/linux', formDataToSend, {
          headers: {
            'Content-Type': 'multipart/form-data'
          }
        })

        setSuccess(true)
        setTimeout(() => {
          navigate('/remediations')
        }, 2000)
      } else {
        // Windows rollback
        const formDataToSend = new FormData()
        formDataToSend.append('host', host)
        formDataToSend.append('username', formData.username || 'Administrator')
        formDataToSend.append('password', formData.password)
        if (selectedBackup) formDataToSend.append('backup_id', selectedBackup)

        const response = await api.post('/rollback/windows', formDataToSend, {
          headers: {
            'Content-Type': 'multipart/form-data'
          }
        })

        setSuccess(true)
        setTimeout(() => {
          navigate('/remediations')
        }, 2000)
      }
    } catch (err) {
      console.error('Rollback error:', err)
      setError(err.response?.data?.detail || err.message || 'Failed to execute rollback')
    } finally {
      setLoading(false)
    }
  }

  const isLinux = osType === 'linux' || osType.startsWith('ubuntu') || osType.startsWith('debian')

  return (
    <div className="rollback-page">
      <div className="page-header">
        <h1>Rollback System</h1>
        <button onClick={() => navigate('/remediations')} className="back-btn">
          ← Back to Remediations
        </button>
      </div>

      <div className="rollback-container">
        <form onSubmit={handleSubmit} className="rollback-form">
          <div className="form-section">
            <h2>Target Host</h2>
            
            <div className="form-group">
              <label htmlFor="host">Host *</label>
              <input
                id="host"
                name="host"
                type="text"
                value={host}
                onChange={handleChange}
                placeholder="192.168.1.100"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="osType">OS Type *</label>
              <select
                id="osType"
                name="osType"
                value={osType}
                onChange={handleChange}
                required
              >
                <option value="linux">Linux</option>
                <option value="ubuntu-20.04">Ubuntu 20.04</option>
                <option value="ubuntu-22.04">Ubuntu 22.04</option>
                <option value="debian-12">Debian 12</option>
                <option value="windows-10">Windows 10</option>
                <option value="windows-11">Windows 11</option>
              </select>
            </div>

          </div>

          {remediationInfo && (
            <div className="form-section remediation-info-section">
              <h2>Remediation Information</h2>
              <div className="remediation-info-card">
                <div className="info-row">
                  <strong>Remediation ID:</strong>
                  <code>{remediationInfo.remediationId || 'N/A'}</code>
                </div>
                {remediationInfo.ruleId && (
                  <div className="info-row">
                    <strong>Rule ID:</strong>
                    <span>{remediationInfo.ruleId}</span>
                  </div>
                )}
                <div className="info-row">
                  <strong>Selected Backup:</strong>
                  <code>{selectedBackup || 'Not selected'}</code>
                </div>
                <p className="info-note">
                  This rollback will restore the system to the state before this remediation was applied.
                </p>
              </div>
            </div>
          )}

          {backups.length > 0 && (
            <div className="form-section">
              <h2>Select Backup Version</h2>
              {remediationInfo && (
                <p className="section-note">
                  The backup created for this remediation is automatically selected below.
                </p>
              )}
              
              <div className="backups-list">
                {backups.map((backup) => {
                  const backupId = backup.backup_id || backup._id
                  const timestamp = backup.timestamp || backup.created_at
                  const isSelected = selectedBackup === backupId
                  
                  return (
                    <div
                      key={backupId}
                      className={`backup-item ${isSelected ? 'selected' : ''} ${remediationInfo && remediationInfo.selectedBackup === backupId ? 'remediation-backup' : ''}`}
                      onClick={() => setSelectedBackup(backupId)}
                    >
                      <div className="backup-header">
                        <input
                          type="radio"
                          name="backup"
                          value={backupId}
                          checked={isSelected}
                          onChange={() => setSelectedBackup(backupId)}
                        />
                        <div className="backup-info">
                          <strong>Backup ID: {backupId}</strong>
                          {remediationInfo && remediationInfo.selectedBackup === backupId && (
                            <span className="backup-badge">This Remediation's Backup</span>
                          )}
                          <span className="backup-date">
                            <Clock size={14} />
                            {timestamp ? new Date(timestamp).toLocaleString() : 'Unknown date'}
                          </span>
                        </div>
                      </div>
                      <div className="backup-details">
                        <span className="backup-type">{backup.type || 'pre_remediation_backup'}</span>
                        {backup.os_type && (
                          <span className="backup-os">{backup.os_type}</span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>

              {selectedBackup && (
                <div className="selected-backup-info">
                  <CheckCircle size={16} />
                  <span>Selected backup: {selectedBackup}</span>
                </div>
              )}
            </div>
          )}

          {backups.length === 0 && host && !loadingBackups && (
            <div className="no-backups">
              <AlertCircle size={24} />
              <p>No backups found for this host.</p>
              <small>Run a remediation first to create a backup.</small>
            </div>
          )}

          {isLinux && (
            <div className="form-section">
              <h2>Connection Details</h2>
              
              <div className="form-group">
                <label>Host</label>
                <div className="host-display">
                  <strong>{host || 'Not specified'}</strong>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="username">Username</label>
                <input
                  id="username"
                  name="username"
                  type="text"
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="root or your-username"
                />
              </div>


              <div className="form-group">
                <label htmlFor="password">Password (if not using SSH key)</label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="SSH password"
                />
              </div>

              <div className="form-group">
                <label htmlFor="sudo_password">Sudo Password</label>
                <input
                  id="sudo_password"
                  name="sudo_password"
                  type="password"
                  value={formData.sudo_password}
                  onChange={handleChange}
                  placeholder="Sudo password if required"
                />
              </div>
            </div>
          )}

          {!isLinux && (
            <div className="form-section">
              <h2>Windows Connection</h2>
              
              <div className="form-group">
                <label>Host</label>
                <div className="host-display">
                  <strong>{host || 'Not specified'}</strong>
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="username">Username</label>
                <input
                  id="username"
                  name="username"
                  type="text"
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="Administrator"
                />
              </div>

              <div className="form-group">
                <label htmlFor="password">Password *</label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Windows password"
                  required
                />
              </div>
            </div>
          )}

          {error && (
            <div className="error-banner">
              <AlertCircle size={20} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="success-banner">
              <CheckCircle size={20} />
              <span>Rollback completed successfully! Redirecting...</span>
            </div>
          )}

          <div className="form-actions">
            <button type="button" onClick={() => navigate('/remediations')} className="btn-secondary">
              Cancel
            </button>
            <button 
              type="submit" 
              disabled={loading || !host || (backups.length > 0 && !selectedBackup)} 
              className="btn-primary"
            >
              {loading ? (
                <>
                  <Loader size={18} className="spinner" />
                  Executing Rollback...
                </>
              ) : (
                <>
                  <RotateCcw size={18} />
                  Execute Rollback
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

