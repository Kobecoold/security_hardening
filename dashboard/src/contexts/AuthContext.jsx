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
  const [userRole, setUserRole] = useState(null)

  useEffect(() => {
    // Load API key and user info from localStorage
    const savedKey = localStorage.getItem('api_key')
    const savedUserInfo = localStorage.getItem('user_info')
    
    if (savedUserInfo) {
      try {
        const userInfo = JSON.parse(savedUserInfo)
        setUserRole(userInfo.role || 'user')
      } catch (e) {
        console.error('Error parsing user info:', e)
      }
    }
    
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
          
          // Try to get user info if available (for API key login)
          try {
            const userInfo = localStorage.getItem('user_info')
            if (userInfo) {
              const parsed = JSON.parse(userInfo)
              setUserRole(parsed.role || 'user')
              console.log('Loaded user role from localStorage:', parsed.role)
            }
          } catch (e) {
            // Ignore error
          }
          
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

  const loginWithUser = async (username, password) => {
    try {
      if (!username || !password) {
        return { success: false, error: 'Username and password are required' }
      }

      // Call backend login endpoint
      const formData = new FormData()
      formData.append('username', username)
      formData.append('password', password)
      
      const response = await api.post('/auth/users/login', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })
      
      if (response.data.api_key) {
        // Store API key from login response
        const apiKey = response.data.api_key
        localStorage.setItem('api_key', apiKey)
        if (response.data.user) {
          const userRole = response.data.user.role || 'user'
          localStorage.setItem('user_info', JSON.stringify(response.data.user))
          setUserRole(userRole)
          console.log('User logged in with role:', userRole, 'isAdmin:', userRole === 'admin')
        }
        setApiKey(apiKey)
        api.setApiKey(apiKey)
        
        // Test connection with the new API key
        const isAuthenticated = await testConnection(apiKey)
        if (isAuthenticated) {
          return { success: true }
        } else {
          localStorage.removeItem('api_key')
          localStorage.removeItem('user_info')
          setApiKey(null)
          api.setApiKey(null)
          return { success: false, error: 'Login successful but connection test failed' }
        }
      } else {
        throw new Error('No API key received from server')
      }
    } catch (error) {
      console.error('User login error:', error)
      const errorMsg = error.response?.data?.detail || error.message || 'Failed to login'
      localStorage.removeItem('api_key')
      localStorage.removeItem('user_info')
      setApiKey(null)
      api.setApiKey(null)
      return { success: false, error: errorMsg }
    }
  }

  const logout = () => {
    localStorage.removeItem('api_key')
    localStorage.removeItem('user_info')
    setApiKey(null)
    api.setApiKey(null)
    setIsAuthenticated(false)
    setUserRole(null)
  }

  const isAdmin = userRole === 'admin'

  const value = {
    apiKey,
    isAuthenticated,
    loading,
    userRole,
    isAdmin,
    login,
    loginWithUser,
    logout
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

