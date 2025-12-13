import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { Database, RefreshCw, Plus, Calendar, Server, Clock, Trash2, Play, Pause, Eye } from 'lucide-react'
import './SystemBackups.css'

export default function SystemBackups() {
  const navigate = useNavigate()
  const { userRole } = useAuth()
  const [systemBackups, setSystemBackups] = useState([])
  const [scheduledBackups, setScheduledBackups] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [showScheduleForm, setShowScheduleForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [filter, setFilter] = useState('all')
  const [hostFilter, setHostFilter] = useState('')

  const [formData, setFormData] = useState({
    host: '',
    osType: 'linux',
    username: '',
    password: '',
    sudo_password: '',
    backupOptions: {
      ssh_config: true,
      users_groups: true,
      network_config: true,
      security_config: true,
      system_services: true,
      firewall_config: true,
      logging_config: true,
      system_info: true
    }
  })

  const [scheduleData, setScheduleData] = useState({
    host: '',
    osType: 'linux',
    username: '',
    password: '',
    sudo_password: '',
    scheduleType: 'daily', // daily, weekly, monthly
    time: '02:00', // HH:MM format
    enabled: true,
    backupOptions: {
      ssh_config: true,
      users_groups: true,
      network_config: true,
      security_config: true,
      system_services: true,
      firewall_config: true,
      logging_config: true,
      system_info: true
    }
  })

  useEffect(() => {
    if (userRole !== 'admin') {
      navigate('/backups')
    } else {
      loadSystemBackups()
      loadScheduledBackups()
    }
  }, [userRole, filter])

  const loadSystemBackups = async () => {
    try {
      setLoading(true)
      const response = await api.get('/backups/system', {
        params: {
          os_type: filter !== 'all' ? filter : undefined
        }
      })
      setSystemBackups(response.data.backups || [])
      setError(null)
    } catch (err) {
      console.error('Error loading system backups:', err)
      setError(err.response?.data?.detail || 'Failed to load system backups')
    } finally {
      setLoading(false)
    }
  }

  const loadScheduledBackups = async () => {
    try {
      const response = await api.get('/backups/schedules')
      setScheduledBackups(response.data.schedules || [])
    } catch (err) {
      console.error('Error loading scheduled backups:', err)
    }
  }

  const handleCreateBackup = async (e) => {
    e.preventDefault()
    setCreating(true)
    setError(null)

    try {
      const formDataToSend = new FormData()
      if (formData.osType === 'linux' || formData.osType.startsWith('ubuntu') || formData.osType.startsWith('debian')) {
        formDataToSend.append('Host', formData.host)
        formDataToSend.append('Username', formData.username)
        if (formData.password) formDataToSend.append('Password', formData.password)
        if (formData.sudo_password) formDataToSend.append('Sudo_password', formData.sudo_password)
        // Add backup options
        Object.keys(formData.backupOptions).forEach(key => {
          formDataToSend.append(`backup_${key}`, formData.backupOptions[key].toString())
        })

        const response = await api.post('/backups/system/linux', formDataToSend, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })

        alert('System backup created successfully!')
        setShowCreateForm(false)
        setFormData({
          host: '',
          osType: 'linux',
          username: '',
          password: '',
          sudo_password: '',
          backupOptions: {
            ssh_config: true,
            users_groups: true,
            network_config: true,
            security_config: true,
            system_services: true,
            firewall_config: true,
            logging_config: true,
            system_info: true
          }
        })
        loadSystemBackups()
      } else {
        formDataToSend.append('host', formData.host)
        formDataToSend.append('username', formData.username || 'Administrator')
        formDataToSend.append('password', formData.password)
        // Add backup options for Windows
        Object.keys(formData.backupOptions).forEach(key => {
          formDataToSend.append(`backup_${key}`, formData.backupOptions[key].toString())
        })

        const response = await api.post('/backups/system/windows', formDataToSend, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })

        alert('System backup created successfully!')
        setShowCreateForm(false)
        setFormData({
          host: '',
          osType: 'linux',
          username: '',
          password: '',
          sudo_password: '',
          backupOptions: {
            ssh_config: true,
            users_groups: true,
            network_config: true,
            security_config: true,
            system_services: true,
            firewall_config: true,
            logging_config: true,
            system_info: true
          }
        })
        loadSystemBackups()
      }
    } catch (err) {
      console.error('Error creating backup:', err)
      setError(err.response?.data?.detail || 'Failed to create system backup')
    } finally {
      setCreating(false)
    }
  }

  const handleCreateSchedule = async (e) => {
    e.preventDefault()
    setCreating(true)
    setError(null)

    try {
      const formDataToSend = new FormData()
      formDataToSend.append('host', scheduleData.host)
      formDataToSend.append('osType', scheduleData.osType)
      formDataToSend.append('username', scheduleData.username)
      if (scheduleData.password) formDataToSend.append('password', scheduleData.password)
      if (scheduleData.sudo_password) formDataToSend.append('sudo_password', scheduleData.sudo_password)
      formDataToSend.append('scheduleType', scheduleData.scheduleType)
      formDataToSend.append('time', scheduleData.time)
      formDataToSend.append('enabled', scheduleData.enabled.toString())
      // Add backup options
      Object.keys(scheduleData.backupOptions).forEach(key => {
        formDataToSend.append(`backup_${key}`, scheduleData.backupOptions[key].toString())
      })

      const response = await api.post('/backups/schedules', formDataToSend, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      alert('Scheduled backup created successfully!')
      setShowScheduleForm(false)
      setScheduleData({
        host: '',
        osType: 'linux',
        username: '',
        password: '',
        sudo_password: '',
        scheduleType: 'daily',
        time: '02:00',
        enabled: true,
        backupOptions: {
          ssh_config: true,
          users_groups: true,
          network_config: true,
          security_config: true,
          system_services: true,
          firewall_config: true,
          logging_config: true,
          system_info: true
        }
      })
      loadScheduledBackups()
    } catch (err) {
      console.error('Error creating schedule:', err)
      setError(err.response?.data?.detail || 'Failed to create scheduled backup')
    } finally {
      setCreating(false)
    }
  }

  const handleDeleteSchedule = async (scheduleId) => {
    if (!window.confirm('Are you sure you want to delete this scheduled backup?')) {
      return
    }

    try {
      await api.delete(`/backups/schedules/${scheduleId}`)
      loadScheduledBackups()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to delete schedule')
    }
  }

  const handleToggleSchedule = async (scheduleId, enabled) => {
    try {
      const formData = new FormData()
      formData.append('enabled', (!enabled).toString())
      await api.patch(`/backups/schedules/${scheduleId}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      loadScheduledBackups()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to toggle schedule')
    }
  }

  const handleDeleteBackup = async (backupId) => {
    if (!window.confirm('Are you sure you want to delete this backup?')) {
      return
    }

    try {
      await api.delete(`/backups/${backupId}`)
      loadSystemBackups()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to delete backup')
    }
  }

  const getFilteredBackups = () => {
    let filtered = systemBackups

    if (hostFilter) {
      filtered = filtered.filter(b => 
        b.host?.toLowerCase().includes(hostFilter.toLowerCase())
      )
    }

    return filtered
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'Unknown'
    try {
      return new Date(dateString).toLocaleString()
    } catch {
      return dateString
    }
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading system backups...</p>
      </div>
    )
  }

  const filteredBackups = getFilteredBackups()

  return (
    <div className="system-backups-page">
      <div className="page-header">
        <h1>System Backups</h1>
        <div className="header-actions">
          <button onClick={() => setShowScheduleForm(true)} className="btn-schedule">
            <Calendar size={18} />
            Schedule Backup
          </button>
          <button onClick={() => setShowCreateForm(true)} className="btn-create">
            <Plus size={18} />
            Create Backup
          </button>
          <button onClick={loadSystemBackups} className="refresh-btn">
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

      {/* Scheduled Backups Section */}
      {scheduledBackups.length > 0 && (
        <div className="scheduled-section">
          <h2>Scheduled Backups</h2>
          <div className="schedules-list">
            {scheduledBackups.map((schedule) => (
              <div key={schedule._id || schedule.id} className="schedule-card">
                <div className="schedule-header">
                  <div>
                    <strong>{schedule.host}</strong>
                    <span className="schedule-type">{schedule.scheduleType}</span>
                    <span className="schedule-time">
                      <Clock size={14} />
                      {schedule.time}
                    </span>
                  </div>
                  <div className="schedule-actions">
                    <button
                      onClick={() => handleToggleSchedule(schedule._id || schedule.id, schedule.enabled)}
                      className={`btn-toggle ${schedule.enabled ? 'enabled' : 'disabled'}`}
                    >
                      {schedule.enabled ? <Pause size={14} /> : <Play size={14} />}
                      {schedule.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      onClick={() => handleDeleteSchedule(schedule._id || schedule.id)}
                      className="btn-delete-small"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="backups-filters">
        <div className="filter-group">
          <label>
            <Server size={16} />
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

      {/* System Backups List */}
      {filteredBackups.length === 0 ? (
        <div className="empty-state">
          <Database size={48} />
          <h3>No system backups found</h3>
          <p>Create a system backup to get started.</p>
        </div>
      ) : (
        <div className="backups-grid">
          {filteredBackups.map((backup) => {
            const backupId = backup.backup_id || backup._id
            const timestamp = backup.timestamp || backup.created_at

            return (
              <div key={backupId} className="backup-card">
                <div className="backup-header">
                  <div className="backup-id">
                    <Database size={18} />
                    <span className="id-text">{backupId}</span>
                  </div>
                  <span className={`os-badge ${backup.os_type || 'unknown'}`}>
                    {(backup.os_type || 'unknown').toUpperCase()}
                  </span>
                </div>

                <div className="backup-details">
                  <div className="detail-row">
                    <strong>Host:</strong>
                    <span>{backup.host || 'Unknown'}</span>
                  </div>

                  <div className="detail-row">
                    <strong>Type:</strong>
                    <span>System Backup</span>
                  </div>

                  <div className="detail-row">
                    <Calendar size={14} />
                    <span>{formatDate(timestamp)}</span>
                  </div>
                </div>

                <div className="backup-actions">
                  <button
                    onClick={() => navigate(`/backups/${backupId}`)}
                    className="btn-view"
                  >
                    <Eye size={14} />
                    View Details
                  </button>
                  <button
                    onClick={() => handleDeleteBackup(backupId)}
                    className="btn-delete"
                  >
                    <Trash2 size={14} />
                    Delete
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create Backup Modal */}
      {showCreateForm && (
        <div className="modal-overlay" onClick={() => setShowCreateForm(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Create System Backup</h2>
            <form onSubmit={handleCreateBackup}>
              <div className="form-group">
                <label>Host *</label>
                <input
                  type="text"
                  value={formData.host}
                  onChange={(e) => setFormData({ ...formData, host: e.target.value })}
                  placeholder="192.168.1.100"
                  required
                />
              </div>

              <div className="form-group">
                <label>OS Type *</label>
                <select
                  value={formData.osType}
                  onChange={(e) => setFormData({ ...formData, osType: e.target.value })}
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

              {(formData.osType === 'linux' || formData.osType.startsWith('ubuntu') || formData.osType.startsWith('debian')) ? (
                <>
                  <div className="form-group">
                    <label>Username</label>
                    <input
                      type="text"
                      value={formData.username}
                      onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                      placeholder="root or your-username"
                    />
                  </div>

                  <div className="form-group">
                    <label>Password</label>
                    <input
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      placeholder="SSH password"
                    />
                  </div>

                  <div className="form-group">
                    <label>Sudo Password</label>
                    <input
                      type="password"
                      value={formData.sudo_password}
                      onChange={(e) => setFormData({ ...formData, sudo_password: e.target.value })}
                      placeholder="Sudo password if required"
                    />
                  </div>

                  <div className="form-group">
                    <label>Backup Options *</label>
                    <div className="backup-options">
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.ssh_config}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, ssh_config: e.target.checked }
                          })}
                        />
                        <span>SSH Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.users_groups}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, users_groups: e.target.checked }
                          })}
                        />
                        <span>Users & Groups</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.network_config}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, network_config: e.target.checked }
                          })}
                        />
                        <span>Network Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.security_config}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, security_config: e.target.checked }
                          })}
                        />
                        <span>Security Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.system_services}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, system_services: e.target.checked }
                          })}
                        />
                        <span>System Services</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.firewall_config}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, firewall_config: e.target.checked }
                          })}
                        />
                        <span>Firewall Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.logging_config}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, logging_config: e.target.checked }
                          })}
                        />
                        <span>Logging Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.system_info}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, system_info: e.target.checked }
                          })}
                        />
                        <span>System Information</span>
                      </label>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="form-group">
                    <label>Username</label>
                    <input
                      type="text"
                      value={formData.username}
                      onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                      placeholder="Administrator"
                    />
                  </div>

                  <div className="form-group">
                    <label>Password *</label>
                    <input
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      placeholder="Windows password"
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label>Backup Options *</label>
                    <div className="backup-options">
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.ssh_config}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, ssh_config: e.target.checked }
                          })}
                        />
                        <span>Registry Keys</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.users_groups}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, users_groups: e.target.checked }
                          })}
                        />
                        <span>Security Policies</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.firewall_config}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, firewall_config: e.target.checked }
                          })}
                        />
                        <span>Firewall Rules</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={formData.backupOptions.system_info}
                          onChange={(e) => setFormData({
                            ...formData,
                            backupOptions: { ...formData.backupOptions, system_info: e.target.checked }
                          })}
                        />
                        <span>System Information</span>
                      </label>
                    </div>
                  </div>
                </>
              )}

              <div className="modal-actions">
                <button type="button" onClick={() => setShowCreateForm(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={creating} className="btn-primary">
                  {creating ? 'Creating...' : 'Create Backup'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Schedule Backup Modal */}
      {showScheduleForm && (
        <div className="modal-overlay" onClick={() => setShowScheduleForm(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Schedule System Backup</h2>
            <form onSubmit={handleCreateSchedule}>
              <div className="form-group">
                <label>Host *</label>
                <input
                  type="text"
                  value={scheduleData.host}
                  onChange={(e) => setScheduleData({ ...scheduleData, host: e.target.value })}
                  placeholder="192.168.1.100"
                  required
                />
              </div>

              <div className="form-group">
                <label>OS Type *</label>
                <select
                  value={scheduleData.osType}
                  onChange={(e) => setScheduleData({ ...scheduleData, osType: e.target.value })}
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

              <div className="form-group">
                <label>Schedule Type *</label>
                <select
                  value={scheduleData.scheduleType}
                  onChange={(e) => setScheduleData({ ...scheduleData, scheduleType: e.target.value })}
                  required
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>

              <div className="form-group">
                <label>Time (HH:MM) *</label>
                <input
                  type="time"
                  value={scheduleData.time}
                  onChange={(e) => setScheduleData({ ...scheduleData, time: e.target.value })}
                  required
                />
              </div>

              {(scheduleData.osType === 'linux' || scheduleData.osType.startsWith('ubuntu') || scheduleData.osType.startsWith('debian')) ? (
                <>
                  <div className="form-group">
                    <label>Username</label>
                    <input
                      type="text"
                      value={scheduleData.username}
                      onChange={(e) => setScheduleData({ ...scheduleData, username: e.target.value })}
                      placeholder="root or your-username"
                    />
                  </div>

                  <div className="form-group">
                    <label>Password</label>
                    <input
                      type="password"
                      value={scheduleData.password}
                      onChange={(e) => setScheduleData({ ...scheduleData, password: e.target.value })}
                      placeholder="SSH password"
                    />
                  </div>

                  <div className="form-group">
                    <label>Sudo Password</label>
                    <input
                      type="password"
                      value={scheduleData.sudo_password}
                      onChange={(e) => setScheduleData({ ...scheduleData, sudo_password: e.target.value })}
                      placeholder="Sudo password if required"
                    />
                  </div>

                  <div className="form-group">
                    <label>Backup Options *</label>
                    <div className="backup-options">
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.ssh_config}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, ssh_config: e.target.checked }
                          })}
                        />
                        <span>SSH Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.users_groups}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, users_groups: e.target.checked }
                          })}
                        />
                        <span>Users & Groups</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.network_config}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, network_config: e.target.checked }
                          })}
                        />
                        <span>Network Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.security_config}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, security_config: e.target.checked }
                          })}
                        />
                        <span>Security Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.system_services}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, system_services: e.target.checked }
                          })}
                        />
                        <span>System Services</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.firewall_config}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, firewall_config: e.target.checked }
                          })}
                        />
                        <span>Firewall Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.logging_config}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, logging_config: e.target.checked }
                          })}
                        />
                        <span>Logging Configuration</span>
                      </label>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={scheduleData.backupOptions.system_info}
                          onChange={(e) => setScheduleData({
                            ...scheduleData,
                            backupOptions: { ...scheduleData.backupOptions, system_info: e.target.checked }
                          })}
                        />
                        <span>System Information</span>
                      </label>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="form-group">
                    <label>Username</label>
                    <input
                      type="text"
                      value={scheduleData.username}
                      onChange={(e) => setScheduleData({ ...scheduleData, username: e.target.value })}
                      placeholder="Administrator"
                    />
                  </div>

                  <div className="form-group">
                    <label>Password *</label>
                    <input
                      type="password"
                      value={scheduleData.password}
                      onChange={(e) => setScheduleData({ ...scheduleData, password: e.target.value })}
                      placeholder="Windows password"
                      required
                    />
                  </div>
                </>
              )}

              <div className="modal-actions">
                <button type="button" onClick={() => setShowScheduleForm(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={creating} className="btn-primary">
                  {creating ? 'Creating...' : 'Create Schedule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

