import React, { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import api from '../services/api'
import { Wrench, Loader, AlertCircle, CheckCircle, Server } from 'lucide-react'
import './RemediationForm.css'

export default function RemediationForm() {
  const navigate = useNavigate()
  const location = useLocation()
  const [loading, setLoading] = useState(false)
  const [loadingRules, setLoadingRules] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  // Get host and OS from location state (from audit detail page)
  const { host, osType, auditId } = location.state || {}

  const [formData, setFormData] = useState({
    host: host || '',
    os_type: osType || 'linux',
    rule_id: '',
    username: '',
    key_path: '~/.ssh/id_ed25519',
    password: '',
    use_sudo: true,
    sudo_password: '',
    create_backup: true
  })

  const [availableRules, setAvailableRules] = useState([])
  const [failedRules, setFailedRules] = useState([])

  useEffect(() => {
    if (auditId) {
      loadFailedRulesFromAudit(auditId)
    } else if (formData.host && formData.os_type) {
      loadAvailableRules()
    }
  }, [auditId, formData.host, formData.os_type])

  const loadFailedRulesFromAudit = async (auditId) => {
    try {
      setLoadingRules(true)
      const response = await api.get(`/reports/audits/${auditId}`)
      const audit = response.data
      
      // Filter failed rules
      const failed = (audit.results || []).filter(r => 
        r.exit_status !== 0 && r.status !== 'PASS' && r.status !== 'SKIPPED'
      )
      
      setFailedRules(failed)
      setFormData(prev => ({
        ...prev,
        host: audit.host || prev.host,
        os_type: audit.os_type || prev.os_type
      }))
    } catch (err) {
      console.error('Error loading audit:', err)
    } finally {
      setLoadingRules(false)
    }
  }

  const loadAvailableRules = async () => {
    try {
      setLoadingRules(true)
      const response = await api.get(`/rules?os_name=${formData.os_type}`)
      const rules = response.data.rules || []
      setAvailableRules(rules)
    } catch (err) {
      console.error('Error loading rules:', err)
    } finally {
      setLoadingRules(false)
    }
  }

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
      if (formData.os_type === 'linux' || formData.os_type.startsWith('ubuntu') || formData.os_type.startsWith('debian')) {
        // Linux remediation
        const formDataToSend = new FormData()
        formDataToSend.append('Host', formData.host)
        formDataToSend.append('Username', formData.username)
        if (formData.key_path) formDataToSend.append('Key_path', formData.key_path)
        if (formData.password) formDataToSend.append('Password', formData.password)
        formDataToSend.append('Use_sudo', formData.use_sudo)
        if (formData.sudo_password) formDataToSend.append('Sudo_password', formData.sudo_password)
        formDataToSend.append('Rule_id', formData.rule_id)
        formDataToSend.append('create_backup', formData.create_backup)

        const response = await api.post('/remediate/linux', formDataToSend, {
          headers: {
            'Content-Type': 'multipart/form-data'
          }
        })

        setSuccess(true)
        setTimeout(() => {
          navigate('/remediations')
        }, 2000)
      } else {
        // Windows remediation
        const formDataToSend = new FormData()
        formDataToSend.append('host', formData.host)
        formDataToSend.append('username', formData.username || 'Administrator')
        formDataToSend.append('password', formData.password)
        formDataToSend.append('script_name', 'fix-security-policies.ps1')
        formDataToSend.append('create_backup', formData.create_backup)

        const response = await api.post('/remediate/windows', formDataToSend, {
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
      console.error('Remediation error:', err)
      setError(err.response?.data?.detail || err.message || 'Failed to run remediation')
    } finally {
      setLoading(false)
    }
  }

  const isLinux = formData.os_type === 'linux' || 
                  formData.os_type?.startsWith('ubuntu') || 
                  formData.os_type?.startsWith('debian')

  return (
    <div className="remediation-form-page">
      <div className="page-header">
        <h1>Run Remediation</h1>
        <button onClick={() => navigate('/remediations')} className="back-btn">
          ← Back to Remediations
        </button>
      </div>

      <div className="remediation-form-container">
        <form onSubmit={handleSubmit} className="remediation-form">
          <div className="form-section">
            <h2>Target Host</h2>
            
            <div className="form-group">
              <label htmlFor="host">Host *</label>
              <input
                id="host"
                name="host"
                type="text"
                value={formData.host}
                onChange={handleChange}
                placeholder="192.168.1.100"
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="os_type">OS Type</label>
              <select
                id="os_type"
                name="os_type"
                value={formData.os_type}
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

          {isLinux && (
            <>
              <div className="form-section">
                <h2>Rule to Fix</h2>
                
                {failedRules.length > 0 ? (
                  <div className="form-group">
                    <label htmlFor="rule_id">Select Failed Rule *</label>
                    <select
                      id="rule_id"
                      name="rule_id"
                      value={formData.rule_id}
                      onChange={handleChange}
                      required
                    >
                      <option value="">-- Select a failed rule --</option>
                      {failedRules.map((rule) => (
                        <option key={rule.id} value={rule.id}>
                          {rule.id} - {rule.title}
                        </option>
                      ))}
                    </select>
                    <small>Rules from latest audit that failed</small>
                  </div>
                ) : (
                  <div className="form-group">
                    <label htmlFor="rule_id">Rule ID *</label>
                    <input
                      id="rule_id"
                      name="rule_id"
                      type="text"
                      value={formData.rule_id}
                      onChange={handleChange}
                      placeholder="cis-ubuntu-20.04-5.2.4"
                      required
                    />
                    <small>Enter the rule ID you want to fix</small>
                  </div>
                )}
              </div>

              <div className="form-section">
                <h2>Connection Details</h2>
                
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

                <div className="form-group checkbox-group">
                  <label>
                    <input
                      type="checkbox"
                      name="use_sudo"
                      checked={formData.use_sudo}
                      onChange={handleChange}
                    />
                    Use sudo (required for most remediations)
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
            </>
          )}

          {!isLinux && (
            <div className="form-section">
              <h2>Windows Connection</h2>
              
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

          <div className="form-section">
            <h2>Backup Options</h2>
            
            <div className="form-group checkbox-group">
              <label>
                <input
                  type="checkbox"
                  name="create_backup"
                  checked={formData.create_backup}
                  onChange={handleChange}
                />
                Create backup before remediation (recommended)
              </label>
              <small>Allows you to rollback changes if needed</small>
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
              <span>Remediation started successfully! Redirecting...</span>
            </div>
          )}

          <div className="form-actions">
            <button type="button" onClick={() => navigate('/remediations')} className="btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn-primary">
              {loading ? (
                <>
                  <Loader size={18} className="spinner" />
                  Running Remediation...
                </>
              ) : (
                <>
                  <Wrench size={18} />
                  Start Remediation
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

