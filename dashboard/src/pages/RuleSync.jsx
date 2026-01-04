import React, { useState, useEffect } from 'react'
import api from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { Upload, Link as LinkIcon, RefreshCw, CheckCircle, AlertCircle, FilePlus, Globe, ListChecks } from 'lucide-react'
import './RuleSync.css'

const OS_OPTIONS = [
  { value: 'ubuntu-22.04', label: 'Ubuntu 22.04' },
  { value: 'ubuntu-20.04', label: 'Ubuntu 20.04' },
  { value: 'debian-12', label: 'Debian 12' },
  { value: 'windows-11', label: 'Windows 11' },
  { value: 'windows-10', label: 'Windows 10' },
]

const SOURCE_OPTIONS = [
  { value: 'ssg', label: 'SCAP Security Guide (SSG/OpenSCAP)' },
  { value: 'stig', label: 'STIG' },
  { value: 'sct', label: 'Microsoft SCT' },
  { value: 'cis', label: 'CIS (upload licensed content)' },
]

const FORMAT_OPTIONS = [
  { value: '', label: 'Auto-detect' },
  { value: 'xccdf', label: 'XCCDF / SCAP XML' },
  { value: 'yaml', label: 'YAML bundle' },
]

const TEMPLATES = [
  {
    label: 'SSG Ubuntu 22.04 Level 1 (xccdf)',
    os_name: 'ubuntu-22.04',
    source: 'ssg',
    profile: 'level1-server',
    url: 'https://github.com/ComplianceAsCode/content/releases/latest/download/ssg-ubuntu2204-xccdf.xml',
    format_hint: 'xccdf',
  },
  {
    label: 'SSG Ubuntu 20.04 Level 1 (xccdf)',
    os_name: 'ubuntu-20.04',
    source: 'ssg',
    profile: 'level1-server',
    url: 'https://github.com/ComplianceAsCode/content/releases/latest/download/ssg-ubuntu2004-xccdf.xml',
    format_hint: 'xccdf',
  },
  {
    label: 'SSG Debian 12 Level 1 (xccdf)',
    os_name: 'debian-12',
    source: 'ssg',
    profile: 'level1-server',
    url: 'https://github.com/ComplianceAsCode/content/releases/latest/download/ssg-debian12-xccdf.xml',
    format_hint: 'xccdf',
  },
  {
    label: 'Windows 10 STIG (upload local) - template',
    os_name: 'windows-10',
    source: 'stig',
    profile: 'stig',
    url: '',
    format_hint: 'xccdf',
  },
]

export default function RuleSync() {
  const { userRole } = useAuth()
  const [form, setForm] = useState({
    os_name: 'ubuntu-22.04',
    source: 'ssg',
    profile: 'level1',
    url: '',
    format_hint: '',
  })
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(null)
  const [error, setError] = useState(null)
  const [rulesPreview, setRulesPreview] = useState({ loading: false, rules: [], error: null })

  if (userRole !== 'admin') {
    return (
      <div className="rulesync-page">
        <div className="error-banner">
          <AlertCircle size={18} />
          <span>Only admins can sync rules.</span>
        </div>
      </div>
    )
  }

  const handleChange = (e) => {
    const { name, value } = e.target
    setForm((prev) => ({ ...prev, [name]: value }))
  }

  const handleFileChange = (e) => {
    setFile(e.target.files?.[0] || null)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setSuccess(null)

    if (!form.url && !file) {
      setError('Cần cung cấp URL hoặc upload file SCAP/XCCDF/YAML.')
      return
    }

    try {
      setLoading(true)
      const fd = new FormData()
      fd.append('os_name', form.os_name)
      fd.append('source', form.source)
      fd.append('profile', form.profile)
      if (form.url) fd.append('url', form.url)
      if (form.format_hint) fd.append('format_hint', form.format_hint)
      if (file) fd.append('uploaded_file', file)

      const resp = await api.post('/rules/sync', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })

      setSuccess(resp.data)
    } catch (err) {
      console.error('Rule sync error', err)
      setError(err.response?.data?.detail || err.message || 'Sync failed')
    } finally {
      setLoading(false)
    }
  }

  const applyTemplate = (tpl) => {
    setForm({
      os_name: tpl.os_name,
      source: tpl.source,
      profile: tpl.profile,
      url: tpl.url,
      format_hint: tpl.format_hint,
    })
    setFile(null)
  }

  // Preview current rules for selected OS (helps confirm auto rules are loaded)
  const loadPreviewRules = async () => {
    setRulesPreview({ loading: true, rules: [], error: null })
    try {
      const resp = await api.get(`/rules?os_name=${form.os_name}`)
      const rules = resp.data.rules || []
      setRulesPreview({ loading: false, rules, error: null })
    } catch (err) {
      setRulesPreview({
        loading: false,
        rules: [],
        error: err.response?.data?.detail || err.message || 'Failed to load rules',
      })
    }
  }

  useEffect(() => {
    // Auto-refresh preview when OS changes
    loadPreviewRules()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.os_name])

  return (
    <div className="rulesync-page">
      <div className="page-header">
        <div className="title-wrap">
          <FilePlus size={22} />
          <div>
            <h1>Rule Sync (Auto Import)</h1>
            <p className="subtitle">
              Kéo rule từ SCAP/XCCDF/YAML vào <code>content/rules/auto</code> để dùng ngay trong audit/remediation.
            </p>
          </div>
        </div>
        <button onClick={() => window.location.reload()} className="refresh-btn">
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <form className="rulesync-form" onSubmit={handleSubmit}>
        <div className="form-grid">
          <div className="form-group">
            <label>OS *</label>
            <select name="os_name" value={form.os_name} onChange={handleChange}>
              {OS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label>Source *</label>
            <select name="source" value={form.source} onChange={handleChange}>
              {SOURCE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label>Profile/Baseline</label>
            <input
              name="profile"
              type="text"
              value={form.profile}
              onChange={handleChange}
              placeholder="level1, level2, workstation, server..."
            />
          </div>

          <div className="form-group">
            <label>Format Hint</label>
            <select name="format_hint" value={form.format_hint} onChange={handleChange}>
              {FORMAT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="form-group">
          <label>Source URL (SCAP/XCCDF/YAML)</label>
          <div className="input-with-icon">
            <LinkIcon size={16} />
            <input
              name="url"
              type="text"
              value={form.url}
              onChange={handleChange}
              placeholder="https://example.com/ssg-ubuntu2204-xccdf.xml"
            />
          </div>
          <small>Hỗ trợ http/https. Nếu bỏ trống, dùng file upload bên dưới.</small>
        </div>

        <div className="form-group">
          <label>Upload File (tùy chọn)</label>
          <div className="file-input">
            <label className="file-btn">
              <Upload size={16} />
              <span>{file ? file.name : 'Chọn file SCAP/XCCDF hoặc YAML'}</span>
              <input type="file" accept=".xml,.yaml,.yml,.zip,.gz,.xz,.json" onChange={handleFileChange} />
            </label>
          </div>
          <small>Nếu cung cấp cả URL và file, file sẽ được ưu tiên.</small>
        </div>

        {error && (
          <div className="error-banner">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="success-banner">
            <CheckCircle size={18} />
            <div className="success-text">
              <div><strong>Synced:</strong> {success.total_rules} rules</div>
              <div><strong>Saved to:</strong> {success.saved_to}</div>
              <div><strong>Source:</strong> {success.source} | <strong>Profile:</strong> {success.profile}</div>
              <div><strong>OS:</strong> {success.os}</div>
            </div>
          </div>
        )}

        <div className="info-callout">
          <Globe size={18} />
          <div>
            <strong>Nguồn mở gợi ý:</strong> SCAP Security Guide (complianceascode/SSG) có profile cho Ubuntu/Debian và STIG cho Windows.
            Với CIS có bản quyền, hãy tải SCAP chính thức rồi upload tại đây.
          </div>
        </div>

        <div className="templates-section">
          <div className="templates-header">
            <ListChecks size={18} />
            <strong>Templates nhanh (SSG/STIG)</strong>
          </div>
          <div className="templates-grid">
            {TEMPLATES.map((tpl) => (
              <button
                type="button"
                key={tpl.label}
                className="template-btn"
                onClick={() => applyTemplate(tpl)}
              >
                {tpl.label}
              </button>
            ))}
          </div>
          <small>Chọn template để tự điền URL/profile/OS. Với STIG Windows, hãy upload file bạn có quyền.</small>
        </div>

        <div className="preview-card">
          <div className="preview-header">
            <span><strong>Rule preview</strong> – OS: {form.os_name}</span>
            <button type="button" className="refresh-btn" onClick={loadPreviewRules}>
              <RefreshCw size={14} />
              Reload
            </button>
          </div>
          {rulesPreview.loading ? (
            <div className="preview-loading">Loading rules...</div>
          ) : rulesPreview.error ? (
            <div className="error-banner">
              <AlertCircle size={16} />
              <span>{rulesPreview.error}</span>
            </div>
          ) : (
            <div className="preview-body">
              <div className="preview-meta">
                <div>Total rules: <strong>{rulesPreview.rules.length}</strong></div>
                <div>Hiển thị tối đa 20 rule đầu tiên</div>
              </div>
              <div className="rule-list">
                {rulesPreview.rules.slice(0, 20).map((r) => (
                  <div key={r.id || r.title} className="rule-item">
                    <div className="rule-id">{r.id || 'no-id'}</div>
                    <div className="rule-title">{r.title || r.description || ''}</div>
                    <div className={`rule-sev ${r.severity || 'unknown'}`}>{r.severity || 'unknown'}</div>
                  </div>
                ))}
                {rulesPreview.rules.length === 0 && (
                  <div className="preview-empty">Chưa có rule cho OS này hoặc cần sync.</div>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="form-actions">
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Syncing...' : 'Sync Rules'}
          </button>
        </div>
      </form>
    </div>
  )
}

