import React from 'react'
import { Outlet, Link, useLocation } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { 
  LayoutDashboard, 
  Server, 
  FileCheck, 
  Wrench,
  LogOut,
  Database,
  Users,
  FilePlus
} from 'lucide-react'
import './Layout.css'

export default function Layout() {
  const location = useLocation()
  const { logout, userRole } = useAuth()

  const navItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/hosts', label: 'Hosts', icon: Server },
    { path: '/audits', label: 'Audits', icon: FileCheck },
    { path: '/remediations', label: 'Remediations', icon: Wrench },
    { path: '/backups', label: 'Rule Backups', icon: Database },
    ...(userRole === 'admin' ? [
      { path: '/system-backups', label: 'System Backups', icon: Database },
      { path: '/rules/sync', label: 'Rule Sync', icon: FilePlus },
      { path: '/users', label: 'Users', icon: Users }
    ] : [])
  ]

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>🔒 Security Hardening</h1>
        </div>
        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const Icon = item.icon
            // Check if current path matches or starts with the nav item path
            let isActive = false
            if (item.path === '/') {
              // For root path, only match exactly
              isActive = location.pathname === '/'
            } else {
              // For other paths, match if pathname starts with the item path
              isActive = location.pathname === item.path || location.pathname.startsWith(item.path + '/')
            }
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon size={20} />
                <span>{item.label}</span>
              </Link>
            )
          })}
        </nav>
        <div className="sidebar-footer">
          <button onClick={logout} className="logout-btn">
            <LogOut size={20} />
            <span>Logout</span>
          </button>
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}

