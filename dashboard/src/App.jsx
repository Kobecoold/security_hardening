import React, { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Hosts from './pages/Hosts'
import Audits from './pages/Audits'
import Remediations from './pages/Remediations'
import AuditDetail from './pages/AuditDetail'
import AuditForm from './pages/AuditForm'
import RemediationForm from './pages/RemediationForm'
import Rollback from './pages/Rollback'
import Backups from './pages/Backups'
import BackupDetail from './pages/BackupDetail'
import SystemBackups from './pages/SystemBackups'
import Users from './pages/Users'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import Login from './pages/Login'
import './App.css'

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth()
  
  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    )
  }
  
  return isAuthenticated ? children : <Navigate to="/login" />
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="hosts" element={<Hosts />} />
        <Route path="audits" element={<Audits />} />
        <Route path="audits/:id" element={<AuditDetail />} />
        <Route path="audit/new" element={<AuditForm osType="linux" />} />
        <Route path="audit/new/windows" element={<AuditForm osType="windows" />} />
        <Route path="remediations" element={<Remediations />} />
        <Route path="remediate/new" element={<RemediationForm />} />
        <Route path="rollback" element={<Rollback />} />
        <Route path="backups" element={<Backups />} />
        <Route path="backups/:id" element={<BackupDetail />} />
        <Route path="system-backups" element={<SystemBackups />} />
        <Route path="users" element={<Users />} />
      </Route>
    </Routes>
  )
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <AppRoutes />
      </Router>
    </AuthProvider>
  )
}

export default App

