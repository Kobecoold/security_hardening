import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import api from '../services/api'
import { Shield, User, UserPlus } from 'lucide-react'
import './Login.css'

export default function Login() {
  const [loginMode, setLoginMode] = useState('user') // 'user' or 'register'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [registerData, setRegisterData] = useState({
    username: '',
    password: '',
    email: ''
  })
  const [hasUsers, setHasUsers] = useState(true) // Assume users exist until checked
  const { loginWithUser } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    checkIfUsersExist()
  }, [])

  const checkIfUsersExist = async () => {
    try {
      const response = await api.get('/auth/users/count')
      const userCount = response.data.count || 0
      setHasUsers(userCount > 0)
      if (userCount === 0) {
        setLoginMode('register') // Auto-switch to register if no users
      }
    } catch (err) {
      console.error('Error checking users:', err)
      // If endpoint doesn't exist or fails, assume users exist
      setHasUsers(true)
    }
  }

  const handleUserLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const result = await loginWithUser(username, password)
      if (result.success) {
        navigate('/')
      } else {
        setError(result.error || 'Invalid username or password.')
        console.error('Login failed:', result.error)
      }
    } catch (err) {
      console.error('Login exception:', err)
      setError(err.message || 'Failed to connect. Please check your credentials and backend connection.')
    } finally {
      setLoading(false)
    }
  }

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('username', registerData.username)
      formData.append('password', registerData.password)
      formData.append('email', registerData.email)
      // Role is determined by backend - first user is admin, others are user

      const response = await api.post('/auth/users/register', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      if (response.data.status === 'success') {
        // Auto login after registration
        const loginResult = await loginWithUser(registerData.username, registerData.password)
        if (loginResult.success) {
          navigate('/')
        } else {
          setError('Registration successful but login failed. Please try logging in.')
        }
      }
    } catch (err) {
      console.error('Registration error:', err)
      setError(err.response?.data?.detail || err.message || 'Failed to register user')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <div className="login-icon">
            <Shield size={48} />
          </div>
          <h1>Security Hardening</h1>
          <p>Sign in to continue</p>
        </div>

        <div className="login-mode-tabs">
          <button
            className={`tab ${loginMode === 'user' ? 'active' : ''}`}
            onClick={() => setLoginMode('user')}
          >
            <User size={18} />
            Login
          </button>
          <button
            className={`tab ${loginMode === 'register' ? 'active' : ''}`}
            onClick={() => setLoginMode('register')}
          >
            <UserPlus size={18} />
            Register
          </button>
        </div>

        {loginMode === 'user' ? (
          <form onSubmit={handleUserLogin} className="login-form">
            <div className="form-group">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
              />
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" disabled={loading} className="login-button">
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleRegister} className="login-form">
            <div className="form-group">
              <label htmlFor="reg-username">Username *</label>
              <input
                id="reg-username"
                type="text"
                value={registerData.username}
                onChange={(e) => setRegisterData({ ...registerData, username: e.target.value })}
                placeholder="Enter username"
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-password">Password *</label>
              <input
                id="reg-password"
                type="password"
                value={registerData.password}
                onChange={(e) => setRegisterData({ ...registerData, password: e.target.value })}
                placeholder="Enter password (min 6 characters)"
                required
                minLength={6}
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-email">Email</label>
              <input
                id="reg-email"
                type="email"
                value={registerData.email}
                onChange={(e) => setRegisterData({ ...registerData, email: e.target.value })}
                placeholder="user@example.com"
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-role">Role</label>
              <input
                id="reg-role"
                type="text"
                value={hasUsers ? 'User (View Only)' : 'Admin (Full Access)'}
                disabled
                className="disabled-input"
              />
              <small>
                {hasUsers
                  ? 'Only one admin account is allowed. New users can only be created as regular users.'
                  : 'This will be the first admin account.'}
              </small>
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" disabled={loading} className="login-button">
              {loading ? 'Registering...' : 'Register'}
            </button>
          </form>
        )}

        <div className="login-footer">
          {loginMode === 'user' && (
            <p>First time? <button type="button" onClick={() => setLoginMode('register')} className="link-button">Register here</button></p>
          )}
          {loginMode === 'register' && (
            <p>Already have an account? <button type="button" onClick={() => setLoginMode('user')} className="link-button">Login here</button></p>
          )}
        </div>
      </div>
    </div>
  )
}

