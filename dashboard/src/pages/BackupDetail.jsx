import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { ArrowLeft, Database, Calendar, Server, RotateCcw, AlertCircle, Trash2 } from 'lucide-react'
import './BackupDetail.css'

export default function BackupDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { userRole } = useAuth()
  const [backup, setBackup] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedSections, setExpandedSections] = useState({})
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    loadBackupDetail()
  }, [id])

  const loadBackupDetail = async () => {
    try {
      setLoading(true)
      setError(null)

      // Try to find backup from all sources
      let foundBackup = null

      // Try Linux backups
      try {
        const linuxResponse = await api.get('/backups/linux')
        const linuxBackups = linuxResponse.data.backups || []
        foundBackup = linuxBackups.find(b => 
          (b.backup_id || b._id) === id
        )
        if (foundBackup) {
          foundBackup.os_type = 'linux'
        }
      } catch (err) {
        console.error('Error loading Linux backups:', err)
      }

      // Try Windows backups if not found
      if (!foundBackup) {
        try {
          const windowsResponse = await api.get('/backups/windows')
          const windowsBackups = windowsResponse.data.backups || []
          foundBackup = windowsBackups.find(b => 
            (b.backup_id || b._id) === id
          )
          if (foundBackup) {
            foundBackup.os_type = foundBackup.os_type || 'windows'
          }
        } catch (err) {
          console.error('Error loading Windows backups:', err)
        }
      }

      if (!foundBackup) {
        setError('Backup not found')
        return
      }

      setBackup(foundBackup)
    } catch (err) {
      console.error('Error loading backup detail:', err)
      setError(err.response?.data?.detail || 'Failed to load backup details')
    } finally {
      setLoading(false)
    }
  }

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }))
  }

  const handleRollback = () => {
    navigate('/rollback', {
      state: {
        host: backup.host,
        osType: backup.os_type || 'linux',
        selectedBackup: backup.backup_id || backup._id
      }
    })
  }

  const handleDelete = async () => {
    const backupId = backup.backup_id || backup._id
    if (!window.confirm(`Are you sure you want to delete backup ${backupId}? This action cannot be undone.`)) {
      return
    }

    try {
      setDeleting(true)
      await api.delete(`/backups/${backupId}`)
      alert('Backup deleted successfully')
      navigate('/backups')
    } catch (err) {
      console.error('Error deleting backup:', err)
      alert(err.response?.data?.detail || 'Failed to delete backup')
    } finally {
      setDeleting(false)
    }
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'Unknown'
    try {
      return new Date(dateString).toLocaleString()
    } catch {
      return dateString
    }
  }

  const formatDataSize = (data) => {
    if (!data) return '0 bytes'
    const jsonStr = JSON.stringify(data)
    const bytes = new Blob([jsonStr]).size
    if (bytes < 1024) return `${bytes} bytes`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading backup details...</p>
      </div>
    )
  }

  if (error || !backup) {
    return (
      <div className="backup-detail-page">
        <div className="error-banner">
          <AlertCircle size={20} />
          <span>{error || 'Backup not found'}</span>
        </div>
        <button onClick={() => navigate('/backups')} className="back-btn">
          <ArrowLeft size={18} />
          Back to Backups
        </button>
      </div>
    )
  }

  const backupId = backup.backup_id || backup._id
  const osType = backup.os_type || 'unknown'

  return (
    <div className="backup-detail-page">
      <div className="page-header">
        <div>
          <button onClick={() => navigate('/backups')} className="back-btn">
            <ArrowLeft size={18} />
            Back to Backups
          </button>
          <h1>Backup Details</h1>
        </div>
        {userRole === 'admin' && (
          <div style={{ display: 'flex', gap: '12px' }}>
            <button onClick={handleRollback} className="btn-rollback-large">
              <RotateCcw size={18} />
              Rollback to this Backup
            </button>
            <button 
              onClick={handleDelete} 
              className="btn-delete-large"
              disabled={deleting}
            >
              <Trash2 size={18} />
              {deleting ? 'Deleting...' : 'Delete Backup'}
            </button>
          </div>
        )}
      </div>

      <div className="backup-detail-container">
        <div className="backup-info-card">
          <h2>Backup Information</h2>
          <div className="info-grid">
            <div className="info-item">
              <strong>Backup ID:</strong>
              <code>{backupId}</code>
            </div>
            <div className="info-item">
              <strong>Host:</strong>
              <span>{backup.host || 'Unknown'}</span>
            </div>
            <div className="info-item">
              <strong>OS Type:</strong>
              <span className={`os-badge ${osType}`}>
                {osType.toUpperCase()}
              </span>
            </div>
            <div className="info-item">
              <strong>Type:</strong>
              <span>{backup.type || 'pre_remediation_backup'}</span>
            </div>
            <div className="info-item">
              <Calendar size={16} />
              <strong>Created:</strong>
              <span>{formatDate(backup.timestamp || backup.created_at)}</span>
            </div>
            {backup.data && (
              <div className="info-item">
                <strong>Data Size:</strong>
                <span>{formatDataSize(backup.data)}</span>
              </div>
            )}
          </div>
        </div>

        {backup.data && Object.keys(backup.data).length > 0 && (
          <div className="backup-data-card">
            <h2>Backup Data</h2>
            <div className="data-sections">
              {Object.entries(backup.data).map(([key, value]) => (
                <div key={key} className="data-section">
                  <button
                    className="section-header"
                    onClick={() => toggleSection(key)}
                  >
                    <span className="section-title">{key}</span>
                    <span className="section-toggle">
                      {expandedSections[key] ? '−' : '+'}
                    </span>
                  </button>
                  {expandedSections[key] && (
                    <div className="section-content">
                      {typeof value === 'string' ? (
                        <pre className="data-content">{value}</pre>
                      ) : (
                        <pre className="data-content">
                          {JSON.stringify(value, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {backup.rollback_details && (
          <div className="rollback-details-card">
            <h2>Rollback Details</h2>
            <pre className="rollback-content">
              {JSON.stringify(backup.rollback_details, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

