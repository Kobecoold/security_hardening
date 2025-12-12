import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  }
})

let currentApiKey = null

api.setApiKey = (key) => {
  currentApiKey = key
  if (key) {
    api.defaults.headers.common['X-API-Key'] = key
  } else {
    delete api.defaults.headers.common['X-API-Key']
  }
}

// Request interceptor to add API key
api.interceptors.request.use(
  (config) => {
    if (currentApiKey) {
      config.headers['X-API-Key'] = currentApiKey
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Log error for debugging
    if (error.response) {
      console.error('API Error:', {
        status: error.response.status,
        statusText: error.response.statusText,
        data: error.response.data,
        url: error.config?.url
      })
    } else if (error.request) {
      console.error('Network Error:', 'No response received', error.request)
    } else {
      console.error('Error:', error.message)
    }

    if (error.response?.status === 401) {
      // Unauthorized - clear API key
      localStorage.removeItem('api_key')
      currentApiKey = null
      delete api.defaults.headers.common['X-API-Key']
    }
    return Promise.reject(error)
  }
)

export default api

