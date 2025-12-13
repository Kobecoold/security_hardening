import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'
import { Users, Plus, RefreshCw, Shield, User, Mail, AlertCircle, Edit, Trash2, KeyRound } from 'lucide-react'
import './Users.css'

export default function UsersPage() {
  const navigate = useNavigate()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const [deletingUser, setDeletingUser] = useState(null)

  const [newUser, setNewUser] = useState({
    username: '',
    password: '',
    email: '',
    role: 'user'
  })

  const [editUser, setEditUser] = useState({
    email: '',
    password: '',
    confirmPassword: ''
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
      // Role luôn là 'user' - không gửi role từ client (backend sẽ force)

      const response = await api.post('/auth/users/create', formData, {
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

  const handleEditUser = (user) => {
    setEditingUser(user)
    setEditUser({
      email: user.email || '',
      password: '',
      confirmPassword: ''
    })
    setError(null)
  }

  const handleUpdateUser = async (e) => {
    e.preventDefault()
    setError(null)

    // Validate password if provided
    if (editUser.password) {
      if (editUser.password.length < 6) {
        setError('Password must be at least 6 characters long')
        return
      }
      if (editUser.password !== editUser.confirmPassword) {
        setError('Passwords do not match')
        return
      }
    }

    setCreating(true)

    try {
      const formData = new FormData()
      if (editUser.email !== editingUser.email) {
        formData.append('email', editUser.email)
      }
      if (editUser.password) {
        formData.append('password', editUser.password)
      }

      // Check if there's anything to update
      if (!formData.has('email') && !formData.has('password')) {
        setError('No changes to update')
        setCreating(false)
        return
      }

      const response = await api.put(`/auth/users/${editingUser.username}`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      if (response.data.status === 'success') {
        setEditingUser(null)
        setEditUser({ email: '', password: '', confirmPassword: '' })
        loadUsers()
      }
    } catch (err) {
      console.error('Error updating user:', err)
      setError(err.response?.data?.detail || 'Failed to update user')
    } finally {
      setCreating(false)
    }
  }

  const handleDeleteUser = (user) => {
    setDeletingUser(user)
  }

  const confirmDeleteUser = async () => {
    if (!deletingUser) return

    setError(null)
    setCreating(true)

    try {
      console.log('Deleting user:', deletingUser.username)
      const response = await api.delete(`/auth/users/${deletingUser.username}`)
      console.log('Delete response:', response.data)

      if (response.data.status === 'success') {
        // Remove user from state immediately (optimistic update)
        setUsers(prevUsers => prevUsers.filter(u => u.username !== deletingUser.username))
        setDeletingUser(null)
        // Reload users list to ensure sync
        await loadUsers()
      } else {
        setError('Delete failed: ' + (response.data.message || 'Unknown error'))
      }
    } catch (err) {
      console.error('Error deleting user:', err)
      setError(err.response?.data?.detail || err.message || 'Failed to delete user')
    } finally {
      setCreating(false)
    }
  }

  const handleChangeRole = async (username, newRole) => {
    setError(null)
    setCreating(true)

    try {
      const formData = new FormData()
      formData.append('role', newRole)

      const response = await api.patch(`/auth/users/${username}/role`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      if (response.data.status === 'success') {
        loadUsers()
      }
    } catch (err) {
      console.error('Error changing role:', err)
      setError(err.response?.data?.detail || 'Failed to change user role')
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
                disabled
              >
                <option value="user">User (View Only)</option>
              </select>
              <small>Only one admin account is allowed. New users can only be created as regular users.</small>
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
                {user.role === 'admin' ? <Shield size={24} /> : <User size={24} />}
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
                  <div className="user-role-container">
                    <span className={`user-role ${user.role}`}>
                      {user.role === 'admin' ? <Shield size={14} /> : <User size={14} />}
                      {user.role}
                    </span>
                    {user.role === 'user' && (
                      <button
                        onClick={() => handleChangeRole(user.username, 'admin')}
                        className="btn-change-role"
                        title="Promote to Admin"
                      >
                        <KeyRound size={14} />
                      </button>
                    )}
                    {user.role === 'admin' && (
                      <button
                        onClick={() => handleChangeRole(user.username, 'user')}
                        className="btn-change-role"
                        title="Demote to User"
                        disabled={users.filter(u => u.role === 'admin').length <= 1}
                      >
                        <User size={14} />
                      </button>
                    )}
                  </div>
                </div>
                {user.created_at && (
                  <div className="user-created">
                    Created: {new Date(user.created_at).toLocaleDateString()}
                  </div>
                )}
                <div className="user-actions">
                  <button
                    onClick={() => handleEditUser(user)}
                    className="btn-edit"
                    title="Edit User"
                  >
                    <Edit size={16} />
                    Edit
                  </button>
                  <button
                    onClick={() => handleDeleteUser(user)}
                    className="btn-delete"
                    title="Delete User"
                    disabled={user.role === 'admin' && users.filter(u => u.role === 'admin').length <= 1}
                  >
                    <Trash2 size={16} />
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {editingUser && (
        <div className="modal-overlay" onClick={() => setEditingUser(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Edit User: {editingUser.username}</h2>
            <form onSubmit={handleUpdateUser} className="create-user-form">
              <div className="form-group">
                <label htmlFor="edit-email">Email</label>
                <input
                  id="edit-email"
                  type="email"
                  value={editUser.email}
                  onChange={(e) => setEditUser({ ...editUser, email: e.target.value })}
                  placeholder="user@example.com"
                />
              </div>
              <div className="form-group">
                <label htmlFor="edit-password">New Password (leave empty to keep current)</label>
                <input
                  id="edit-password"
                  type="password"
                  value={editUser.password}
                  onChange={(e) => setEditUser({ ...editUser, password: e.target.value })}
                  placeholder="Enter new password"
                  minLength={6}
                />
              </div>
              {editUser.password && (
                <div className="form-group">
                  <label htmlFor="edit-confirm-password">Confirm New Password *</label>
                  <input
                    id="edit-confirm-password"
                    type="password"
                    value={editUser.confirmPassword}
                    onChange={(e) => setEditUser({ ...editUser, confirmPassword: e.target.value })}
                    placeholder="Confirm new password"
                    minLength={6}
                    required={editUser.password ? true : false}
                  />
                </div>
              )}
              <div className="form-actions">
                <button
                  type="button"
                  onClick={() => {
                    setEditingUser(null)
                    setEditUser({ email: '', password: '', confirmPassword: '' })
                  }}
                  className="btn-cancel"
                >
                  Cancel
                </button>
                <button type="submit" disabled={creating} className="btn-submit">
                  {creating ? 'Updating...' : 'Update User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {deletingUser && (
        <div className="modal-overlay" onClick={() => setDeletingUser(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Delete User</h2>
            <p>Are you sure you want to delete user <strong>{deletingUser.username}</strong>?</p>
            <p className="warning-text">This action cannot be undone.</p>
            <div className="form-actions">
              <button
                type="button"
                onClick={() => setDeletingUser(null)}
                className="btn-cancel"
              >
                Cancel
              </button>
              <button
                onClick={confirmDeleteUser}
                disabled={creating}
                className="btn-delete-confirm"
              >
                {creating ? 'Deleting...' : 'Delete User'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

