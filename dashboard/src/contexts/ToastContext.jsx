import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'

const ToastContext = createContext(null)

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}

function normalizeButtonLabel(btn) {
  const txt = (btn?.innerText || '').replace(/\s+/g, ' ').trim()
  return txt || btn?.getAttribute?.('aria-label') || btn?.getAttribute?.('title') || 'button'
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const timersRef = useRef(new Map())

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
    const timer = timersRef.current.get(id)
    if (timer) {
      clearTimeout(timer)
      timersRef.current.delete(id)
    }
  }, [])

  const pushToast = useCallback((message, { durationMs = 2000 } = {}) => {
    const id = `${Date.now()}_${Math.random().toString(16).slice(2)}`
    setToasts((prev) => [...prev, { id, message }])

    const timer = setTimeout(() => removeToast(id), durationMs)
    timersRef.current.set(id, timer)
    return id
  }, [removeToast])

  // Global: show toast on ANY button click (unless disabled / ignored)
  useEffect(() => {
    const handler = (e) => {
      const target = e.target
      if (!target?.closest) return

      // Ignore clicks inside the toast UI itself
      if (target.closest('[data-toast-ignore="true"]')) return

      const btn = target.closest('button')
      if (!btn) return
      if (btn.disabled) return
      if ((btn.getAttribute('aria-disabled') || '').toLowerCase() === 'true') return

      // Opt-out: allow specific buttons to disable global click toast
      if ((btn.dataset?.toast || '').toLowerCase() === 'off') return

      // Custom message on click if desired
      const custom = btn.dataset?.toastMessage
      if (custom && String(custom).trim()) {
        pushToast(String(custom).trim())
        return
      }

      const label = normalizeButtonLabel(btn)
      pushToast(`Message: ${label}`)
    }

    document.addEventListener('click', handler, true) // capture
    return () => document.removeEventListener('click', handler, true)
  }, [pushToast])

  useEffect(() => {
    return () => {
      for (const [, t] of timersRef.current.entries()) clearTimeout(t)
      timersRef.current.clear()
    }
  }, [])

  const value = useMemo(() => ({
    toasts,
    pushToast,
    removeToast,
  }), [toasts, pushToast, removeToast])

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>
}

