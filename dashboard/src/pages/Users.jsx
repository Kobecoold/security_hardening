import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { Users, Plus, RefreshCw, Shield, User, Mail, AlertCircle } from 'lucide-react'
import './Users.css'

export default function UsersPage() {
  const navigate = useNavigate()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [creating, setCreating] = useState(false)

  const [newUser, setNewUser] = useState({
    username: '',
    password: '',
    email: '',
    role: 'user'
  })

  useEffect(() => {
    loadUsers()
  }, [])

  const loadUsers = async () => {
    try {
      setLoading(true)
      const response = await api.get('/auth/users')
      setUsers(response.data.users || [])
      setError(null)
    } catch (err) {
      console.error('Error loading users:', err)
      setError(err.response?.data?.detail || 'Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  const handleCreateUser = async (e) => {
    e.preventDefault()
    setError(null)
    setCreating(true)

    try {
      const formData = new FormData()
      formData.append('username', newUser.username)
      formData.append('password', newUser.password)
      formData.append('email', newUser.email)
      formData.append('role', newUser.role)

      const response = await api.post('/auth/users/register', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      if (response.data.status === 'success') {
        setShowCreateForm(false)
        setNewUser({ username: '', password: '', email: '', role: 'user' })
        loadUsers()
      }
    } catch (err) {
      console.error('Error creating user:', err)
      setError(err.response?.data?.detail || 'Failed to create user')
    } finally {
      setCreating(false)
    }
  }

  if (loading) {
    return (
      <div className="page-loading">
        <div className="spinner"></div>
        <p>Loading users...</p>
      </div>
    )
  }

  return (
    <div className="users-page">
      <div className="page-header">
        <h1>User Management</h1>
        <div className="header-actions">
          <button onClick={() => setShowCreateForm(!showCreateForm)} className="btn-new-user">
            <Plus size={18} />
            Create User
          </button>
          <button onClick={loadUsers} className="refresh-btn">
            <RefreshCw size={18} />
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

      {showCreateForm && (
        <div className="create-user-card">
          <h2>Create New User</h2>
          <form onSubmit={handleCreateUser} className="create-user-form">
            <div className="form-group">
              <label htmlFor="username">Username *</label>
              <input
                id="username"
                type="text"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                required
                placeholder="Enter username"
              />
            </div>

            <div className="form-group">
              <label htmlFor="password">Password *</label>
              <input
                id="password"
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                required
                placeholder="Enter password"
                minLength={6}
              />
            </div>

            <div className="form-group">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                value={newUser.email}
                onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                placeholder="user@example.com"
              />
            </div>

            <div className="form-group">
              <label htmlFor="role">Role *</label>
              <select
                id="role"
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                required
              >
                <option value="user">User (View Only)</option>
                <option value="admin">Admin (Full Access)</option>
              </select>
            </div>

            <div className="form-actions">
              <button
                type="button"
                onClick={() => setShowCreateForm(false)}
                className="btn-cancel"
              >
                Cancel
              </button>
              <button type="submit" disabled={creating} className="btn-submit">
                {creating ? 'Creating...' : 'Create User'}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="users-info">
        <div className="info-card">
          <Shield size={24} />
          <div>
            <h3>User Roles</h3>
            <p><strong>Admin:</strong> Can create audits, remediations, and manage users</p>
            <p><strong>User:</strong> Can only view reports and data</p>
          </div>
        </div>
      </div>

      {users.length === 0 ? (
        <div className="empty-state">
          <Users size={48} />
          <h3>No users found</h3>
          <p>Create the first user to get started. The first user will be an admin.</p>
        </div>
      ) : (
        <div className="users-list">
          {users.map((user) => (
            <div key={user.username} className="user-card">
              <div className="user-avatar">
                <User size={24} />
              </div>
              <div className="user-info">
                <div className="user-name">{user.username}</div>
                <div className="user-details">
                  {user.email && (
                    <span className="user-email">
                      <Mail size={14} />
                      {user.email}
                    </span>
                  )}
                  <span className={`user-role ${user.role}`}>
                    {user.role === 'admin' ? <Shield size={14} /> : <User size={14} />}
                    {user.role}
                  </span>
                </div>
                {user.created_at && (
                  <div className="user-created">
                    Created: {new Date(user.created_at).toLocaleDateString()}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

