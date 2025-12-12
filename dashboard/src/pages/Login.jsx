import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { Shield, User, Key } from 'lucide-react'
import './Login.css'

export default function Login() {
  const [loginMode, setLoginMode] = useState('user') // 'user' or 'apikey'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
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
            User Login
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
          {loginMode === 'user' ? (
            <p>First time? Register the first user via <code>/auth/users/register</code> endpoint.</p>
          ) : (
            <p>Don't have an API key? Use <code>/auth/setup</code> endpoint to create one.</p>
          )}
        </div>
      </div>
    </div>
  )
}

