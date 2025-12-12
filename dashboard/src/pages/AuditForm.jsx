import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { Server, Loader, AlertCircle, CheckCircle } from 'lucide-react'
import './AuditForm.css'

export default function AuditForm({ osType = 'linux' }) {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [auditId, setAuditId] = useState(null)

  // Form state
  const [formData, setFormData] = useState({
    host: '',
    username: '',
    key_path: '~/.ssh/id_ed25519',
    password: '',
    use_sudo: false,
    sudo_password: ''
  })

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)
    setLoading(true)

    try {
      const formDataToSend = new FormData()
      formDataToSend.append('Host', formData.host)
      formDataToSend.append('Username', formData.username)
      if (formData.key_path) formDataToSend.append('Key_path', formData.key_path)
      if (formData.password) formDataToSend.append('Password', formData.password)
      formDataToSend.append('Use_sudo', formData.use_sudo)
      if (formData.sudo_password) formDataToSend.append('Sudo_password', formData.sudo_password)

      const response = await api.post('/audit/linux', formDataToSend, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      setAuditId(response.data.audit_id)
      setSuccess(true)
      
      // Redirect to audit detail after 2 seconds
      setTimeout(() => {
        if (response.data.audit_id) {
          navigate(`/audits/${response.data.audit_id}`)
        } else {
          navigate('/audits')
        }
      }, 2000)

    } catch (err) {
      console.error('Audit error:', err)
      setError(err.response?.data?.detail || err.message || 'Failed to run audit')
    } finally {
      setLoading(false)
    }
  }

  if (osType === 'windows') {
    return <WindowsAuditForm />
  }

  return (
    <div className="audit-form-page">
      <div className="page-header">
        <h1>Run Linux Audit</h1>
        <button onClick={() => navigate('/audits')} className="back-btn">
          ← Back to Audits
        </button>
      </div>

      <div className="audit-form-container">
        <form onSubmit={handleSubmit} className="audit-form">
          <div className="form-section">
            <h2>Connection Details</h2>
            
            <div className="form-group">
              <label htmlFor="host">Host *</label>
              <input
                id="host"
                name="host"
                type="text"
                value={formData.host}
                onChange={handleChange}
                placeholder="192.168.1.100 or hostname"
                required
              />
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
              <label htmlFor="key_path">SSH Key Path</label>
              <input
                id="key_path"
                name="key_path"
                type="text"
                value={formData.key_path}
                onChange={handleChange}
                placeholder="~/.ssh/id_ed25519"
              />
              <small>Leave empty to use password authentication</small>
            </div>

            <div className="form-group">
              <label htmlFor="password">Password (if not using SSH key)</label>
              <input
                id="password"
                name="password"
                type="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="Password for SSH"
              />
            </div>
          </div>

          <div className="form-section">
            <h2>Privileges</h2>
            
            <div className="form-group checkbox-group">
              <label>
                <input
                  type="checkbox"
                  name="use_sudo"
                  checked={formData.use_sudo}
                  onChange={handleChange}
                />
                Use sudo for commands that require root privileges
              </label>
            </div>

            {formData.use_sudo && (
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
            )}
          </div>

          {error && (
            <div className="error-banner">
              <AlertCircle size={20} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="success-banner">
              <CheckCircle size={20} />
              <span>Audit started successfully! Redirecting...</span>
            </div>
          )}

          <div className="form-actions">
            <button type="button" onClick={() => navigate('/audits')} className="btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn-primary">
              {loading ? (
                <>
                  <Loader size={18} className="spinner" />
                  Running Audit...
                </>
              ) : (
                <>
                  <Server size={18} />
                  Start Audit
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function WindowsAuditForm() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  const [formData, setFormData] = useState({
    host: '',
    username: 'Administrator',
    password: ''
  })

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData(prev => ({ ...prev, [name]: value }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)
    setLoading(true)

    try {
      const formDataToSend = new FormData()
      formDataToSend.append('host', formData.host)
      formDataToSend.append('username', formData.username)
      formDataToSend.append('password', formData.password)

      const response = await api.post('/audit/windows', formDataToSend, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      setSuccess(true)
      setTimeout(() => {
        if (response.data.audit_id) {
          navigate(`/audits/${response.data.audit_id}`)
        } else {
          navigate('/audits')
        }
      }, 2000)

    } catch (err) {
      console.error('Audit error:', err)
      setError(err.response?.data?.detail || err.message || 'Failed to run audit')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="audit-form-page">
      <div className="page-header">
        <h1>Run Windows Audit</h1>
        <button onClick={() => navigate('/audits')} className="back-btn">
          ← Back to Audits
        </button>
      </div>

      <div className="audit-form-container">
        <form onSubmit={handleSubmit} className="audit-form">
          <div className="form-section">
            <h2>WinRM Connection Details</h2>
            
            <div className="form-group">
              <label htmlFor="host">Host *</label>
              <input
                id="host"
                name="host"
                type="text"
                value={formData.host}
                onChange={handleChange}
                placeholder="192.168.1.100 or hostname"
                required
              />
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

            <div className="info-box">
              <p><strong>Note:</strong> Ensure WinRM is enabled on the Windows host. See <code>WINRM_SETUP.md</code> for setup instructions.</p>
            </div>
          </div>

          {error && (
            <div className="error-banner">
              <AlertCircle size={20} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="success-banner">
              <CheckCircle size={20} />
              <span>Audit started successfully! Redirecting...</span>
            </div>
          )}

          <div className="form-actions">
            <button type="button" onClick={() => navigate('/audits')} className="btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn-primary">
              {loading ? (
                <>
                  <Loader size={18} className="spinner" />
                  Running Audit...
                </>
              ) : (
                <>
                  <Server size={18} />
                  Start Audit
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

