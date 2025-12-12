import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { Database, RefreshCw, Filter, RotateCcw, Server, Calendar, Eye } from 'lucide-react'
import './Backups.css'

export default function Backups() {
  const navigate = useNavigate()
  const { userRole } = useAuth()
  const [backups, setBackups] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all') // all, linux, windows
  const [hostFilter, setHostFilter] = useState('')

  useEffect(() => {
    loadBackups()
  }, [filter])

  const loadBackups = async () => {
    try {
      setLoading(true)
      setError(null)

      let allBackups = []

      if (filter === 'all' || filter === 'linux') {
        try {
          const linuxResponse = await api.get('/backups/linux')
          const linuxBackups = (linuxResponse.data.backups || []).map(b => ({
            ...b,
            os_type: 'linux'
          }))
          allBackups = [...allBackups, ...linuxBackups]
        } catch (err) {
          console.error('Error loading Linux backups:', err)
        }
      }

      if (filter === 'all' || filter === 'windows') {
        try {
          const windowsResponse = await api.get('/backups/windows')
          const windowsBackups = (windowsResponse.data.backups || []).map(b => ({
            ...b,
            os_type: b.os_type || 'windows'
          }))
          allBackups = [...allBackups, ...windowsBackups]
        } catch (err) {
          console.error('Error loading Windows backups:', err)
        }
      }

      // Sort by timestamp (newest first)
      allBackups.sort((a, b) => {
        const timeA = new Date(a.timestamp || a.created_at || 0).getTime()
        const timeB = new Date(b.timestamp || b.created_at || 0).getTime()
        return timeB - timeA
      })

      setBackups(allBackups)
    } catch (err) {
      console.error('Error loading backups:', err)
      setError(err.response?.data?.detail || 'Failed to load backups')
    } finally {
      setLoading(false)
    }
  }

  const getFilteredBackups = () => {
    let filtered = backups

    if (hostFilter) {
      filtered = filtered.filter(b => 
        b.host?.toLowerCase().includes(hostFilter.toLowerCase())
      )
    }

    return filtered
  }

  const handleRollback = (backup) => {
    navigate('/rollback', {
      state: {
        host: backup.host,
        osType: backup.os_type || 'linux',
        selectedBackup: backup.backup_id || backup._id
      }
    })
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'Unknown'
    try {
      return new Date(dateString).toLocaleString()
    } catch {
      return dateString
    }
  }

  const getBackupTypeLabel = (type) => {
    if (!type) return 'Backup'
    return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading backups...</p>
      </div>
    )
  }

  const filteredBackups = getFilteredBackups()

  return (
    <div className="backups-page">
      <div className="page-header">
        <h1>System Backups</h1>
        <div className="header-actions">
          <button onClick={loadBackups} className="refresh-btn">
            <RefreshCw size={18} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <span>{error}</span>
        </div>
      )}

      <div className="backups-filters">
        <div className="filter-group">
          <label>
            <Filter size={16} />
            OS Type:
          </label>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
          </select>
        </div>

        <div className="filter-group">
          <label>
            <Server size={16} />
            Host:
          </label>
          <input
            type="text"
            placeholder="Filter by host..."
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
          />
        </div>

        <div className="backup-stats">
          <span>Total: <strong>{filteredBackups.length}</strong></span>
        </div>
      </div>

      {filteredBackups.length === 0 ? (
        <div className="empty-state">
          <Database size={48} />
          <h3>No backups found</h3>
          <p>Backups will appear here after running remediations with backup enabled.</p>
        </div>
      ) : (
        <div className="backups-grid">
          {filteredBackups.map((backup) => {
            const backupId = backup.backup_id || backup._id
            const timestamp = backup.timestamp || backup.created_at
            const osType = backup.os_type || 'unknown'

            return (
              <div key={backupId} className="backup-card">
                <div className="backup-header">
                  <div className="backup-id">
                    <Database size={18} />
                    <span className="id-text">{backupId}</span>
                  </div>
                  <span className={`os-badge ${osType}`}>
                    {osType.toUpperCase()}
                  </span>
                </div>

                <div className="backup-details">
                  <div className="detail-row">
                    <strong>Host:</strong>
                    <span>{backup.host || 'Unknown'}</span>
                  </div>

                  <div className="detail-row">
                    <strong>Type:</strong>
                    <span>{getBackupTypeLabel(backup.type)}</span>
                  </div>

                  <div className="detail-row">
                    <Calendar size={14} />
                    <span>{formatDate(timestamp)}</span>
                  </div>

                  {backup.data && (
                    <div className="detail-row backup-contents">
                      <strong>Backup Contents:</strong>
                      <div className="backup-items">
                        {Object.keys(backup.data)
                          .filter(key => key !== 'backup_info')
                          .map(key => {
                            // Format key names for display
                            let displayName = key
                            if (key.startsWith('file_')) {
                              displayName = key.replace('file_', '').replace(/_/g, '/')
                            } else if (key === 'ssh_config') {
                              displayName = 'SSH Config'
                            } else if (key === 'password_policy') {
                              displayName = 'Password Policy'
                            } else if (key === 'security_policy') {
                              displayName = 'Security Policy'
                            } else if (key === 'audit_logon') {
                              displayName = 'Audit Policy'
                            } else if (key === 'admin_account_active') {
                              displayName = 'Admin Account Status'
                            } else if (key === 'ssh_service_status') {
                              displayName = 'SSH Service Status'
                            } else {
                              displayName = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
                            }
                            return (
                              <span key={key} className="backup-item-tag">
                                {displayName}
                              </span>
                            )
                          })}
                      </div>
                    </div>
                  )}
                </div>

                <div className="backup-actions">
                  <button
                    onClick={() => navigate(`/backups/${backupId}`)}
                    className="btn-view"
                  >
                    <Eye size={14} />
                    View Details
                  </button>
                  {userRole === 'admin' && (
                    <button
                      onClick={() => handleRollback(backup)}
                      className="btn-rollback"
                    >
                      <RotateCcw size={14} />
                      Rollback
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

