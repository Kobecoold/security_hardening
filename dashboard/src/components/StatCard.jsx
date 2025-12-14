import React from 'react'
import './StatCard.css'

export default function StatCard({ title, value, label, icon: Icon, trend, color = '#667eea' }) {
  return (
    <div className="stat-card">
      <div className="stat-card-header">
        <div className="stat-card-icon" style={{ backgroundColor: `${color}20`, color }}>
          {Icon && <Icon size={24} />}
        </div>
        <div className="stat-card-content">
          <h3 className="stat-card-title">{title}</h3>
          <div className="stat-card-value" style={{ color }}>
            {value}
          </div>
          {label && <p className="stat-card-label">{label}</p>}
          {trend && (
            <div className={`stat-card-trend ${trend.type}`}>
              {trend.value}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

