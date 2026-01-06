import React from 'react'
import { useToast } from '../contexts/ToastContext'
import './ToastContainer.css'

export default function ToastContainer() {
  const { toasts, removeToast } = useToast()

  return (
    <div className="toast-container" data-toast-ignore="true">
      {toasts.map((t) => (
        <div key={t.id} className="toast">
          <div className="toast-message">{t.message}</div>
          <button
            type="button"
            className="toast-close"
            onClick={() => removeToast(t.id)}
            aria-label="Close toast"
          >
            ×
          </button>
        </div>
      ))}
    </div>
  )
}

