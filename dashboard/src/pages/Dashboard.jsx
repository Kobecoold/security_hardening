import React, { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import api from '../services/api'
import StatCard from '../components/StatCard'
import { 
  Server, 
  CheckCircle, 
  FileCheck, 
  Wrench,
  TrendingUp,
  AlertCircle,
  Plus,
  Database
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import './Dashboard.css'

export default function Dashboard() {
  const navigate = useNavigate()
  const { isAdmin } = useAuth()
  const [stats, setStats] = useState({
    totalHosts: 0,
    complianceScore: 0,
    totalAudits: 0,
    totalRemediations: 0
  })
  const [complianceData, setComplianceData] = useState([])
  const [osDistribution, setOsDistribution] = useState([])
  const [recentAudits, setRecentAudits] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadDashboardData()
    const interval = setInterval(loadDashboardData, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [])

  const loadDashboardData = async () => {
    try {
      setLoading(true)
      const [hostsRes, statsRes, auditsRes, remediationsRes] = await Promise.all([
        api.get('/reports/hosts'),
        api.get('/reports/compliance-stats'),
        api.get('/reports/audits?limit=5'),
        api.get('/reports/remediations?limit=1')
      ])

      const hosts = hostsRes.data.hosts || []
      const complianceStats = statsRes.data || {}
      const audits = auditsRes.data.audits || []
      const remediations = remediationsRes.data.remediations || []

      // Load backups count
      let backupsCount = 0
      try {
        const linuxBackups = await api.get('/backups/linux')
        const windowsBackups = await api.get('/backups/windows')
        backupsCount = (linuxBackups.data.total || 0) + (windowsBackups.data.total || 0)
      } catch (err) {
        console.error('Error loading backups count:', err)
      }

      setStats({
        totalHosts: hosts.length,
        complianceScore: complianceStats.overall_avg_compliance || 0,
        totalAudits: auditsRes.data.total || 0,
        totalRemediations: remediationsRes.data.total || 0,
        totalBackups: backupsCount
      })

      // Prepare compliance chart data
      const complianceChart = hosts.map(host => ({
        name: host.host || 'Unknown',
        score: host.compliance_score || 0
      }))
      setComplianceData(complianceChart)

      // Prepare OS distribution
      const osCounts = {}
      hosts.forEach(host => {
        const os = host.os_type || 'Unknown'
        osCounts[os] = (osCounts[os] || 0) + 1
      })
      const osData = Object.entries(osCounts).map(([name, value]) => ({
        name,
        value
      }))
      setOsDistribution(osData)

      setRecentAudits(audits)
      setError(null)
    } catch (err) {
      console.error('Error loading dashboard data:', err)
      setError(err.response?.data?.detail || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const COLORS = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b']

  if (loading && stats.totalHosts === 0) {
    return (
      <div className="dashboard-loading">
        <div className="spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    )
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <div className="header-actions">
          {isAdmin && (
            <button onClick={() => navigate('/audit/new')} className="btn-quick-action">
              <Plus size={18} />
              New Audit
            </button>
          )}
          <button onClick={loadDashboardData} className="refresh-btn">
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <AlertCircle size={20} />
          <span>{error}</span>
        </div>
      )}

      <div className="stats-grid">
        <StatCard
          title="Total Hosts"
          value={stats.totalHosts}
          label="Monitored systems"
          icon={Server}
          color="#667eea"
        />
        <StatCard
          title="Compliance Score"
          value={`${stats.complianceScore.toFixed(1)}%`}
          label="Average across all hosts"
          icon={CheckCircle}
          color={stats.complianceScore >= 80 ? '#10b981' : stats.complianceScore >= 50 ? '#f59e0b' : '#ef4444'}
        />
        <StatCard
          title="Total Audits"
          value={stats.totalAudits}
          label="Audit reports"
          icon={FileCheck}
          color="#8b5cf6"
        />
        <StatCard
          title="Remediations"
          value={stats.totalRemediations}
          label="Remediation actions"
          icon={Wrench}
          color="#ec4899"
        />
        <StatCard
          title="Backups"
          value={stats.totalBackups}
          label="System backups"
          icon={Database}
          color="#06b6d4"
        />
      </div>

      <div className="charts-grid">
        <div className="chart-card">
          <h2>Compliance by Host</h2>
          {complianceData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={complianceData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" angle={-45} textAnchor="end" height={80} />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Bar dataKey="score" fill="#667eea" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">No data available</div>
          )}
        </div>

        <div className="chart-card">
          <h2>OS Distribution</h2>
          {osDistribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={osDistribution}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {osDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">No data available</div>
          )}
        </div>
      </div>

      <div className="recent-audits-card">
        <div className="card-header">
          <h2>Recent Audits</h2>
          <Link to="/audits" className="view-all-link">
            View All →
          </Link>
        </div>
        {recentAudits.length > 0 ? (
          <table className="audits-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>OS Type</th>
                <th>Compliance</th>
                <th>Rules</th>
                <th>Date</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {recentAudits.map((audit) => (
                <tr key={audit.id}>
                  <td>{audit.host || 'N/A'}</td>
                  <td>
                    <span className="os-badge">{audit.os_type || 'Unknown'}</span>
                  </td>
                  <td>
                    <span className={`compliance-badge ${
                      (audit.compliance_score || 0) >= 80 ? 'high' :
                      (audit.compliance_score || 0) >= 50 ? 'medium' : 'low'
                    }`}>
                      {(audit.compliance_score || 0).toFixed(1)}%
                    </span>
                  </td>
                  <td>{audit.total_rules || 0}</td>
                  <td>{new Date(audit.created_at).toLocaleString()}</td>
                  <td>
                    <Link to={`/audits/${audit.id}`} className="view-link">
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">No audits found</div>
        )}
      </div>
    </div>
  )
}

