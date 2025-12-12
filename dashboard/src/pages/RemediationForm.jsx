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
    rule_ids: [], // Multi-select rules
    username: '',
    key_path: '~/.ssh/id_ed25519',
    password: '',
    use_sudo: true,
    sudo_password: '',
    create_backup: true
  })

  const [availableRules, setAvailableRules] = useState([])
  const [failedRules, setFailedRules] = useState([])
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    if (auditId) {
      loadFailedRulesFromAudit(auditId)
    }
  }, [auditId])

  useEffect(() => {
    if (formData.os_type && !auditId) {
      loadAvailableRules()
    }
  }, [formData.os_type])

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
      setError('Failed to load rules. Please check OS type.')
    } finally {
      setLoadingRules(false)
    }
  }

  const handleRuleToggle = (ruleId) => {
    setFormData(prev => {
      const currentIds = prev.rule_ids || []
      if (currentIds.includes(ruleId)) {
        return { ...prev, rule_ids: currentIds.filter(id => id !== ruleId) }
      } else {
        return { ...prev, rule_ids: [...currentIds, ruleId] }
      }
    })
  }

  const handleSelectAll = () => {
    const filtered = getFilteredRules()
    const allIds = filtered.map(r => r.id).filter(id => id && id.trim() !== '')
    setFormData(prev => ({ ...prev, rule_ids: allIds }))
  }

  const handleDeselectAll = () => {
    setFormData(prev => ({ ...prev, rule_ids: [] }))
  }

  const getFilteredRules = () => {
    const rulesToShow = failedRules.length > 0 ? failedRules : availableRules
    if (!searchTerm) return rulesToShow
    return rulesToShow.filter(rule => {
      const searchLower = searchTerm.toLowerCase()
      return (
        rule.id?.toLowerCase().includes(searchLower) ||
        rule.title?.toLowerCase().includes(searchLower) ||
        rule.description?.toLowerCase().includes(searchLower)
      )
    })
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
      if (formData.rule_ids.length === 0) {
        setError('Please select at least one rule to fix')
        setLoading(false)
        return
      }

      if (formData.os_type === 'linux' || formData.os_type.startsWith('ubuntu') || formData.os_type.startsWith('debian')) {
        // Linux remediation - run for each selected rule
        const validRuleIds = formData.rule_ids.filter(id => id && id.trim() !== '')
        
        if (validRuleIds.length === 0) {
          setError('Please select at least one valid rule to fix')
          setLoading(false)
          return
        }

        const results = []
        for (let i = 0; i < validRuleIds.length; i++) {
          const ruleId = validRuleIds[i]
          
          if (!ruleId || ruleId.trim() === '') {
            console.warn('Skipping invalid rule ID:', ruleId)
            continue
          }
          
          console.log(`Processing rule ${i + 1}/${validRuleIds.length}: ${ruleId}`)
          
          const formDataToSend = new FormData()
          formDataToSend.append('Host', formData.host)
          formDataToSend.append('Username', formData.username)
          if (formData.key_path) formDataToSend.append('Key_path', formData.key_path)
          if (formData.password) formDataToSend.append('Password', formData.password)
          formDataToSend.append('Use_sudo', formData.use_sudo)
          if (formData.sudo_password) formDataToSend.append('Sudo_password', formData.sudo_password)
          formDataToSend.append('Rule_id', ruleId.trim())
          // Only create backup for first rule
          formDataToSend.append('create_backup', formData.create_backup && i === 0)

          try {
            const response = await api.post('/remediate/linux', formDataToSend, {
              headers: {
                'Content-Type': 'multipart/form-data'
              }
            })
            results.push(response.data)
          } catch (err) {
            console.error(`Error remediating rule ${ruleId}:`, err)
            // Continue with next rule instead of stopping
            results.push({
              rule_id: ruleId,
              status: 'FAILED',
              error: err.response?.data?.detail || err.message
            })
          }
        }

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
                <h2>Select Rules to Fix *</h2>
                
                {loadingRules ? (
                  <div className="loading-rules">
                    <Loader size={20} className="spinner" />
                    <span>Loading rules...</span>
                  </div>
                ) : (
                  <>
                    <div className="rules-header">
                      <div className="form-group">
                        <label htmlFor="search-rules">Search Rules</label>
                        <input
                          id="search-rules"
                          type="text"
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          placeholder="Search by ID, title, or description..."
                        />
                      </div>
                      <div className="rules-actions">
                        <button type="button" onClick={handleSelectAll} className="btn-select-all">
                          Select All
                        </button>
                        <button type="button" onClick={handleDeselectAll} className="btn-deselect-all">
                          Deselect All
                        </button>
                      </div>
                    </div>

                    <div className="rules-selection-info">
                      <span>
                        {formData.rule_ids.length} rule(s) selected
                        {failedRules.length > 0 && ' (from failed audit)'}
                      </span>
                    </div>

                    <div className="rules-list">
                      {getFilteredRules().length === 0 ? (
                        <div className="no-rules">
                          <AlertCircle size={20} />
                          <span>No rules found. {formData.os_type ? `Try changing OS type or check if rules exist for ${formData.os_type}` : 'Please select OS type first'}</span>
                        </div>
                      ) : (
                        getFilteredRules()
                          .filter(rule => rule.id && rule.id.trim() !== '') // Only show rules with valid IDs
                          .map((rule) => {
                            const isSelected = formData.rule_ids.includes(rule.id)
                            return (
                              <div key={rule.id} className={`rule-item ${isSelected ? 'selected' : ''}`}>
                                <label className="rule-checkbox">
                                  <input
                                    type="checkbox"
                                    checked={isSelected}
                                    onChange={() => handleRuleToggle(rule.id)}
                                  />
                                  <div className="rule-info">
                                    <div className="rule-id">{rule.id}</div>
                                    <div className="rule-title">{rule.title || 'No title'}</div>
                                    {rule.description && (
                                      <div className="rule-description">{rule.description}</div>
                                    )}
                                    {rule.level && (
                                      <span className="rule-level">Level: {rule.level}</span>
                                    )}
                                  </div>
                                </label>
                              </div>
                            )
                          })
                      )}
                    </div>
                  </>
                )}
              </div>

              <div className="form-section">
                <h2>Connection Details</h2>
                
                <div className="form-group">
                  <label>Host</label>
                  <div className="host-display">
                    <strong>{formData.host || 'Not specified'}</strong>
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

