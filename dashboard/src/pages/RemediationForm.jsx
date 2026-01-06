import React, { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { Wrench, Loader, AlertCircle, CheckCircle, Server } from 'lucide-react'
import './RemediationForm.css'

export default function RemediationForm() {
  const navigate = useNavigate()
  const location = useLocation()
  const { userRole } = useAuth()
  
  useEffect(() => {
    if (userRole !== 'admin') {
      navigate('/remediations')
    }
  }, [userRole, navigate])
  const [loading, setLoading] = useState(false)
  const [loadingRules, setLoadingRules] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [successMessage, setSuccessMessage] = useState('')

  // Get host and OS from location state (from audit detail page)
  const { host, osType, auditId } = location.state || {}

  const [formData, setFormData] = useState({
    host: host || '',
    os_type: osType || '',  // Empty by default - user must select OS type
    rule_ids: [], // Multi-select rules
    username: '',
    key_path: '',
    password: '',
    use_sudo: true,
    sudo_password: '',
    create_backup: true
  })

  const [availableRules, setAvailableRules] = useState([])
  const [failedRules, setFailedRules] = useState([])
  const [searchTerm, setSearchTerm] = useState('')

  // Helper function to check if a rule ID belongs to Linux or Windows
  const isRuleForOS = (ruleId, osType) => {
    if (!ruleId || !osType) return true // If no info, show all (fallback)
    
    const ruleIdLower = ruleId.toLowerCase()
    const osTypeLower = osType.toLowerCase()
    
    // Windows rules have prefix "winrm-cis-windows"
    const isWindowsRule = ruleIdLower.startsWith('winrm-cis-windows')
    
    // Linux rules have prefix "cis-ubuntu", "cis-debian", or just "cis-" (but not winrm)
    const isLinuxRule = ruleIdLower.startsWith('cis-') && !isWindowsRule
    
    // Check OS type
    const isWindowsOS = osTypeLower.startsWith('windows')
    const isLinuxOS = osTypeLower.startsWith('ubuntu') || osTypeLower.startsWith('debian')
    
    // Match rule to OS
    if (isWindowsOS && isWindowsRule) return true
    if (isLinuxOS && isLinuxRule) return true
    
    // If OS type doesn't match rule type, filter it out
    return false
  }

  useEffect(() => {
    if (auditId) {
      loadFailedRulesFromAudit(auditId)
    }
  }, [auditId])

  useEffect(() => {
    // When host and os_type are provided, load failed rules from latest audit
    if (formData.host && formData.os_type && !auditId) {
      console.log(`Loading failed rules for host: ${formData.host}, OS: ${formData.os_type}`)
      loadFailedRulesFromLatestAudit()
    } else if (formData.os_type && !formData.host && !auditId) {
      // If only os_type is provided, load all available rules (fallback)
      loadAvailableRules()
    }
  }, [formData.host, formData.os_type])

  const loadFailedRulesFromAudit = async (auditId) => {
    try {
      setLoadingRules(true)
      const response = await api.get(`/reports/audits/${auditId}`)
      const audit = response.data
      
      // Get OS type from audit or form
      const auditOSType = audit.os_type || formData.os_type
      
      // Filter failed rules (FAIL, ERROR, or exit_status !== 0)
      // AND filter by OS type
      const failed = (audit.results || []).filter(r => {
        const status = (r.status || '').toUpperCase()
        const isFailed = (
          status === 'FAIL' || 
          status === 'ERROR' || 
          (r.exit_status !== undefined && r.exit_status !== 0 && status !== 'PASS' && status !== 'SKIPPED')
        )
        
        // Also filter by OS type
        const matchesOS = isRuleForOS(r.id, auditOSType)
        
        return isFailed && matchesOS
      })
      
      // Map to rule format with id, title, description, level
      const failedRulesFormatted = failed.map(r => ({
        id: r.id,
        title: r.title || r.id,
        description: r.description || r.reason || '',
        level: r.level || '1',
        status: r.status,
        exit_status: r.exit_status
      }))
      
      setFailedRules(failedRulesFormatted)
      
      // Auto-detect and update OS type from audit
      if (audit.os_type && audit.os_type !== formData.os_type) {
        console.log(`Auto-detected OS type from audit: ${audit.os_type} (was: ${formData.os_type})`)
      }
      
      setFormData(prev => ({
        ...prev,
        host: audit.host || prev.host,
        os_type: audit.os_type || prev.os_type  // Always use OS type from audit if available
      }))
    } catch (err) {
      console.error('Error loading audit:', err)
      setError('Failed to load audit. Please check audit ID.')
    } finally {
      setLoadingRules(false)
    }
  }

  const loadFailedRulesFromLatestAudit = async () => {
    try {
      setLoadingRules(true)
      setError('')
      
      console.log(`🔍 Loading failed rules for host: ${formData.host}, OS type: ${formData.os_type}`)
      
      // Get latest audit for this host
      const auditsResponse = await api.get(`/reports/audits?host=${formData.host}&limit=1`)
      const audits = auditsResponse.data.audits || []
      
      console.log(`📊 Found ${audits.length} audit(s) for host ${formData.host}`)
      
      if (audits.length === 0) {
        const errorMsg = `No audit found for host ${formData.host}. Please run an audit first.`
        setError(errorMsg)
        setFailedRules([])
        console.warn(`⚠️ ${errorMsg}`)
        return
      }
      
      const latestAudit = audits[0]
      console.log(`📋 Latest audit: ID=${latestAudit._id}, OS=${latestAudit.os_type}, Results count=${(latestAudit.results || []).length}`)
      
      // Auto-detect OS type from audit if available, otherwise use form value
      const auditOSType = latestAudit.os_type || formData.os_type
      console.log(`🖥️ Using OS type: ${auditOSType} (from audit: ${latestAudit.os_type || 'N/A'}, from form: ${formData.os_type})`)
      
      // Update form OS type if audit has different OS type (auto-detect)
      if (latestAudit.os_type && latestAudit.os_type !== formData.os_type) {
        console.log(`🔄 Auto-detected OS type from audit: ${latestAudit.os_type} (was: ${formData.os_type})`)
        setFormData(prev => ({
          ...prev,
          os_type: latestAudit.os_type
        }))
      }
      
      // Filter failed rules AND filter by OS type
      const allResults = latestAudit.results || []
      console.log(`🔍 Filtering ${allResults.length} rules...`)
      
      const failed = allResults.filter(r => {
        const status = (r.status || '').toUpperCase()
        const isFailed = (
          status === 'FAIL' || 
          status === 'ERROR' || 
          (r.exit_status !== undefined && r.exit_status !== 0 && status !== 'PASS' && status !== 'SKIPPED')
        )
        
        // Also filter by OS type
        const matchesOS = isRuleForOS(r.id, auditOSType)
        
        if (isFailed) {
          console.log(`  Rule ${r.id}: status=${status}, matchesOS=${matchesOS}, will include=${isFailed && matchesOS}`)
        }
        
        return isFailed && matchesOS
      })
      
      console.log(`✅ Found ${failed.length} failed rules matching OS type ${auditOSType}`)
      
      // Map to rule format
      const failedRulesFormatted = failed.map(r => ({
        id: r.id,
        title: r.title || r.id,
        description: r.description || r.reason || '',
        level: r.level || '1',
        status: r.status,
        exit_status: r.exit_status
      }))
      
      setFailedRules(failedRulesFormatted)
      
      if (failedRulesFormatted.length === 0) {
        const errorMsg = `No failed rules found in the latest audit for ${formData.host} matching OS type "${auditOSType}". All rules are passing or no rules match the detected OS type!`
        setError(errorMsg)
        console.warn(`⚠️ ${errorMsg}`)
      } else {
        console.log(`✅ Successfully loaded ${failedRulesFormatted.length} failed rules`)
      }
    } catch (err) {
      console.error('❌ Error loading latest audit:', err)
      const errorMsg = `Failed to load audit for host ${formData.host}. ${err.response?.data?.detail || err.message}`
      setError(errorMsg)
      setFailedRules([])
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
    setSuccessMessage('')
    setLoading(true)

    try {
      if (formData.rule_ids.length === 0) {
        setError('Please select at least one rule to fix')
        setLoading(false)
        return
      }

      if (formData.os_type.startsWith('ubuntu') || formData.os_type.startsWith('debian')) {
        // Linux remediation - run for each selected rule
        const validRuleIds = formData.rule_ids.filter(id => id && id.trim() !== '')
        
        if (validRuleIds.length === 0) {
          setError('Please select at least one valid rule to fix')
          setLoading(false)
          return
        }

        // Tạo backup chung cho tất cả rules trước (nếu được yêu cầu)
        let batchBackupId = null
        if (formData.create_backup && validRuleIds.length > 0) {
          try {
            console.log(`🛡️ Creating batch backup for ${validRuleIds.length} rules...`)
            const backupFormData = new FormData()
            backupFormData.append('host', formData.host)
            backupFormData.append('os_type', formData.os_type)
            backupFormData.append('rule_ids', validRuleIds.join(','))
            backupFormData.append('Username', formData.username)
            if (formData.key_path) backupFormData.append('Key_path', formData.key_path)
            if (formData.password) backupFormData.append('Password', formData.password)
            if (formData.sudo_password) backupFormData.append('Sudo_password', formData.sudo_password)
            
            const backupResponse = await api.post('/backups/create/batch', backupFormData, {
              headers: { 'Content-Type': 'multipart/form-data' }
            })
            batchBackupId = backupResponse.data.backup_id
            console.log(`✅ Batch backup created: ${batchBackupId}`)
          } catch (err) {
            console.error('⚠️ Batch backup creation failed (non-critical):', err)
            // Tiếp tục remediation dù backup thất bại
          }
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
          // Không tạo backup nữa vì đã tạo batch backup ở trên
          formDataToSend.append('create_backup', false)

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

        setSuccessMessage('Remediation thành công')
        setSuccess(true)
        setTimeout(() => {
          navigate('/remediations')
        }, 2000)
      } else {
        // Windows remediation - run for each selected rule (similar to Linux)
        if (formData.rule_ids.length === 0) {
          setError('Please select at least one rule to fix')
          setLoading(false)
          return
        }

        const validRuleIds = formData.rule_ids.filter(id => id && id.trim() !== '')
        
        if (validRuleIds.length === 0) {
          setError('Please select at least one valid rule to fix')
          setLoading(false)
          return
        }

        // Tạo backup chung cho tất cả rules trước (nếu được yêu cầu)
        let batchBackupId = null
        if (formData.create_backup && validRuleIds.length > 0) {
          try {
            console.log(`🛡️ Creating batch backup for ${validRuleIds.length} Windows rules...`)
            const backupFormData = new FormData()
            backupFormData.append('host', formData.host)
            backupFormData.append('os_type', formData.os_type)
            backupFormData.append('rule_ids', validRuleIds.join(','))
            backupFormData.append('username', formData.username || 'Administrator')
            backupFormData.append('password', formData.password)
            
            const backupResponse = await api.post('/backups/create/batch', backupFormData, {
              headers: { 'Content-Type': 'multipart/form-data' }
            })
            batchBackupId = backupResponse.data.backup_id
            console.log(`✅ Batch backup created: ${batchBackupId}`)
          } catch (err) {
            console.error('⚠️ Batch backup creation failed (non-critical):', err)
            // Tiếp tục remediation dù backup thất bại
          }
        }

        const results = []
        for (let i = 0; i < validRuleIds.length; i++) {
          const ruleId = validRuleIds[i]
          
          if (!ruleId || ruleId.trim() === '') {
            console.warn('Skipping invalid rule ID:', ruleId)
            continue
          }
          
          console.log(`Processing Windows rule ${i + 1}/${validRuleIds.length}: ${ruleId}`)
          
        const formDataToSend = new FormData()
        formDataToSend.append('host', formData.host)
        formDataToSend.append('username', formData.username || 'Administrator')
        formDataToSend.append('password', formData.password)
          formDataToSend.append('rule_id', ruleId.trim())
          // Không tạo backup nữa vì đã tạo batch backup ở trên
          formDataToSend.append('create_backup', false)

          try {
        const response = await api.post('/remediate/windows', formDataToSend, {
          headers: {
            'Content-Type': 'multipart/form-data'
          }
        })
            results.push(response.data)
          } catch (err) {
            console.error(`Error remediating Windows rule ${ruleId}:`, err)
            // Continue with next rule instead of stopping
            results.push({
              rule_id: ruleId,
              status: 'FAILED',
              error: err.response?.data?.detail || err.message
            })
          }
        }

        setSuccessMessage('Remediation thành công')
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

  const isLinux = formData.os_type?.startsWith('ubuntu') || 
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
              <label htmlFor="os_type">OS Type *</label>
              <select
                id="os_type"
                name="os_type"
                value={formData.os_type}
                onChange={handleChange}
                required
              >
                <option value="">-- Select OS Type --</option>
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
                        {failedRules.length > 0 && (
                          <span className="failed-rules-badge">
                            ({failedRules.length} failed rule(s) from latest audit)
                          </span>
                        )}
                      </span>
                    </div>

                    {failedRules.length > 0 && (
                      <div className="info-banner">
                        <AlertCircle size={16} />
                        <span>Showing only FAILED rules from the latest audit for {formData.host}. Only rules that need remediation are displayed.</span>
                      </div>
                    )}

                    <div className="rules-list">
                      {getFilteredRules().length === 0 ? (
                        <div className="no-rules">
                          <AlertCircle size={20} />
                          <span>
                            {formData.host && failedRules.length === 0 
                              ? `No failed rules found for ${formData.host}. All rules are passing! Please run an audit first if you haven't.`
                              : formData.os_type 
                                ? `No rules found. Try changing OS type or check if rules exist for ${formData.os_type}`
                                : 'Please select OS type and enter host first'}
                          </span>
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
                                    <div className="rule-meta">
                                      {rule.level && (
                                        <span className="rule-level">Level: {rule.level}</span>
                                      )}
                                      {rule.status && (
                                        <span className={`rule-status rule-status-${(rule.status || '').toLowerCase()}`}>
                                          Status: {rule.status}
                                        </span>
                                      )}
                                    </div>
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
            <>
              {/* Show failed rules for Windows - same as Linux with selection */}
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
                        {failedRules.length > 0 && (
                          <span className="failed-rules-badge">
                            ({failedRules.length} failed rule(s) from latest audit)
                          </span>
                        )}
                      </span>
                    </div>

                    {failedRules.length > 0 && (
                      <div className="info-banner">
                        <AlertCircle size={16} />
                        <span>Showing only FAILED rules from the latest audit for {formData.host}. Select rules that need remediation.</span>
                      </div>
                    )}

                    {error && (
                      <div className="error-banner" style={{ marginBottom: '1rem' }}>
                        <AlertCircle size={16} />
                        <span>{error}</span>
                      </div>
                    )}

                    <div className="rules-list">
                      {getFilteredRules().length === 0 ? (
                        <div className="no-rules">
                          <AlertCircle size={20} />
                          <span>
                            {error 
                              ? error
                              : formData.host && failedRules.length === 0 
                                ? `No failed rules found for ${formData.host}. All rules are passing! Please run an audit first if you haven't.`
                                : formData.os_type 
                                  ? `No rules found. Try changing OS type or check if rules exist for ${formData.os_type}`
                                  : 'Please select OS type and enter host first'}
                          </span>
                        </div>
                      ) : (
                        getFilteredRules()
                          .filter(rule => rule.id && rule.id.trim() !== '')
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
                                    <div className="rule-meta">
                                      {rule.level && (
                                        <span className="rule-level">Level: {rule.level}</span>
                                      )}
                                      {rule.status && (
                                        <span className={`rule-status rule-status-${(rule.status || '').toLowerCase()}`}>
                                          Status: {rule.status}
                                        </span>
                                      )}
                                    </div>
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
            </>
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
              <span>{successMessage || 'Remediation thành công! Redirecting...'}</span>
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

