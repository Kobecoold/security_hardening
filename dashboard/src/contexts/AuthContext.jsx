import React, { createContext, useContext, useState, useEffect } from 'react'
import api from '../services/api'

const AuthContext = createContext()

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}

export function AuthProvider({ children }) {
  const [apiKey, setApiKey] = useState(null)
  const [loading, setLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  useEffect(() => {
    // Load API key from localStorage
    const savedKey = localStorage.getItem('api_key')
    if (savedKey) {
      setApiKey(savedKey)
      api.setApiKey(savedKey)
      // Test connection
      testConnection(savedKey)
    } else {
      setLoading(false)
    }
  }, [])

  const testConnection = async (key) => {
    try {
      // First test backend is reachable
      const healthResponse = await api.get('/healthz')
      if (healthResponse.status !== 200) {
        setIsAuthenticated(false)
        setLoading(false)
        return false
      }

      // Then test with authenticated endpoint
      try {
        const statsResponse = await api.get('/reports/compliance-stats')
        if (statsResponse.status === 200) {
          setIsAuthenticated(true)
          setLoading(false)
          return true
        } else {
          setIsAuthenticated(false)
          setLoading(false)
          return false
        }
      } catch (error) {
        console.error('Authentication test failed:', error)
        if (error.response?.status === 401) {
          setIsAuthenticated(false)
          setLoading(false)
          return false
        } else {
          // Network error or other issue
          console.error('Unexpected error:', error.response?.data || error.message)
          setIsAuthenticated(false)
          setLoading(false)
          return false
        }
      }
    } catch (error) {
      console.error('Connection test failed:', error)
      setIsAuthenticated(false)
      setLoading(false)
      return false
    }
  }

  const login = async (key) => {
    try {
      if (!key || key.trim() === '') {
        return { success: false, error: 'API key cannot be empty' }
      }

      // Set API key first
      localStorage.setItem('api_key', key.trim())
      setApiKey(key.trim())
      api.setApiKey(key.trim())

      // Test connection
      const isAuthenticated = await testConnection(key.trim())
      
      if (isAuthenticated) {
        return { success: true }
      } else {
        // Clear invalid key
        localStorage.removeItem('api_key')
        setApiKey(null)
        api.setApiKey(null)
        return { success: false, error: 'Invalid API key or connection failed' }
      }
    } catch (error) {
      console.error('Login error:', error)
      localStorage.removeItem('api_key')
      setApiKey(null)
      api.setApiKey(null)
      return { success: false, error: error.message || 'Failed to connect' }
    }
  }

  const logout = () => {
    localStorage.removeItem('api_key')
    setApiKey(null)
    api.setApiKey(null)
    setIsAuthenticated(false)
  }

  const value = {
    apiKey,
    isAuthenticated,
    loading,
    login,
    logout
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

