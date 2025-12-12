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
      const response = await api.get('/healthz')
      if (response.status === 200) {
        // Test with authenticated endpoint
        try {
          await api.get('/reports/compliance-stats')
          setIsAuthenticated(true)
        } catch (error) {
          if (error.response?.status === 401) {
            setIsAuthenticated(false)
          } else {
            setIsAuthenticated(true) // Assume connected if health check passes
          }
        }
      }
    } catch (error) {
      setIsAuthenticated(false)
    } finally {
      setLoading(false)
    }
  }

  const login = async (key) => {
    try {
      localStorage.setItem('api_key', key)
      setApiKey(key)
      api.setApiKey(key)
      await testConnection(key)
      return { success: true }
    } catch (error) {
      return { success: false, error: error.message }
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

