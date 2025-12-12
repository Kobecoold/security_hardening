import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import api from '../services/api'
import { Shield, User, Key, UserPlus } from 'lucide-react'
import './Login.css'

export default function Login() {
  const [loginMode, setLoginMode] = useState('user') // 'user', 'apikey', or 'register'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [registerData, setRegisterData] = useState({
    username: '',
    password: '',
    email: '',
    role: 'admin'
  })
  const { login, loginWithUser } = useAuth()
  const navigate = useNavigate()

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

  const handleApiKeyLogin = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const result = await login(apiKey)
      if (result.success) {
        navigate('/')
      } else {
        setError(result.error || 'Invalid API key. Please check your API key and ensure backend is running.')
        console.error('Login failed:', result.error)
      }
    } catch (err) {
      console.error('Login exception:', err)
      setError(err.message || 'Failed to connect. Please check your API key and backend connection.')
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
      formData.append('role', registerData.role)

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
          <button
            className={`tab ${loginMode === 'apikey' ? 'active' : ''}`}
            onClick={() => setLoginMode('apikey')}
          >
            <Key size={18} />
            API Key
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
        ) : loginMode === 'register' ? (
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
              <label htmlFor="reg-role">Role *</label>
              <select
                id="reg-role"
                value={registerData.role}
                onChange={(e) => setRegisterData({ ...registerData, role: e.target.value })}
                required
              >
                <option value="admin">Admin (Full Access)</option>
                <option value="user">User (View Only)</option>
              </select>
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" disabled={loading} className="login-button">
              {loading ? 'Registering...' : 'Register'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleApiKeyLogin} className="login-form">
            <div className="form-group">
              <label htmlFor="api-key">API Key</label>
              <input
                id="api-key"
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk_..."
                required
                autoFocus
              />
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" disabled={loading} className="login-button">
              {loading ? 'Connecting...' : 'Connect'}
            </button>
          </form>
        )}

        <div className="login-footer">
          {loginMode === 'user' && (
            <p>First time? <button type="button" onClick={() => setLoginMode('register')} className="link-button">Register here</button></p>
          )}
          {loginMode === 'apikey' && (
            <p>Don't have an API key? Use <code>/auth/setup</code> endpoint to create one.</p>
          )}
          {loginMode === 'register' && (
            <p>Already have an account? <button type="button" onClick={() => setLoginMode('user')} className="link-button">Login here</button></p>
          )}
        </div>
      </div>
    </div>
  )
}

