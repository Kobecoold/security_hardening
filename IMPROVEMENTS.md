# Security Hardening - Đề xuất Cải thiện và Phát triển

## 📋 Tổng quan

Tài liệu này tổng hợp các đề xuất cải thiện và tính năng mới cho dự án Security Hardening Agentless.

---

## 🔧 1. CẢI THIỆN REMEDIATION SYSTEM

### 1.1. Chuẩn hóa Remediation Scripts

**Vấn đề hiện tại:**
- Scripts không có cấu trúc thống nhất
- Thiếu error handling và rollback tự động
- Không có verification sau khi chạy remediation
- Windows remediation chỉ có 1 script generic

**Đề xuất:**

#### A. Template chuẩn cho Linux Scripts
```bash
#!/bin/bash
# Remediation script template
# Rule ID: {rule_id}
# OS: {os_type}
# Description: {description}

set -euo pipefail

# Load common functions
source "$(dirname "$0")/_common_functions.sh"

# Pre-remediation check
pre_check() {
    # Verify current state
    # Return 0 if needs remediation, 1 if already compliant
}

# Remediation action
remediate() {
    # Perform remediation
    # Return 0 on success, non-zero on failure
}

# Post-remediation verification
verify() {
    # Verify remediation was successful
    # Return 0 if compliant, 1 if still non-compliant
}

# Main execution
main() {
    log_info "Starting remediation for {rule_id}"
    
    if ! pre_check; then
        log_info "System already compliant, skipping"
        exit 0
    fi
    
    if ! remediate; then
        log_error "Remediation failed"
        exit 1
    fi
    
    if ! verify; then
        log_error "Verification failed - remediation may not have worked"
        exit 1
    fi
    
    log_success "Remediation completed successfully"
    exit 0
}

main "$@"
```

#### B. Cải thiện Windows Remediation
- Tạo scripts riêng cho từng rule (giống Linux)
- Sử dụng PowerShell với error handling
- Thêm verification sau remediation

#### C. Standardize Script Naming
```
Format: {rule_id}-{short-description}.{ext}
Examples:
- cis-ubuntu-20.04-5.2.4-disable-root-login.sh
- cis-windows-10-2.3.1-password-policy.ps1
```

### 1.2. Verification System

**Thêm endpoint:**
```python
@app.post("/remediate/{os_type}/verify", dependencies=[RequireAdmin])
async def verify_remediation(
    host: str = Form(...),
    rule_id: str = Form(...),
    ...
):
    """Verify remediation đã thành công bằng cách chạy lại audit check."""
```

**Logic:**
1. Sau khi remediation xong, tự động chạy lại audit check
2. So sánh kết quả trước/sau
3. Lưu verification status vào remediation log

### 1.3. Dry-run Mode

**Thêm parameter:**
```python
dry_run: bool = Form(False)
```

**Chức năng:**
- Chạy script ở chế độ simulation
- Hiển thị những gì sẽ thay đổi
- Không thực sự thay đổi hệ thống
- Hữu ích cho testing và review

### 1.4. Batch Remediation

**Cải thiện:**
- Hiện tại: Chạy từng rule một
- Đề xuất: Chạy nhiều rules cùng lúc với dependency checking
- Thêm progress tracking cho batch operations

---

## 🚀 2. TÍNH NĂNG MỚI

### 2.1. Scheduled Audits

**Mô tả:**
- Cho phép lên lịch audit tự động (daily/weekly/monthly)
- Gửi email/notification khi có findings
- Tự động tạo reports

**Implementation:**
```python
# Backend: Sử dụng APScheduler hoặc Celery
@app.post("/schedules/audit", dependencies=[RequireAdmin])
async def create_audit_schedule(
    host: str = Form(...),
    schedule_type: str = Form(...),  # daily, weekly, monthly
    time: str = Form(...),  # HH:MM format
    ...
):
    """Tạo scheduled audit."""
```

**Frontend:**
- Trang "Schedules" mới
- Calendar view cho scheduled tasks
- Enable/disable schedules

### 2.2. Compliance Dashboard

**Mô tả:**
- Dashboard hiển thị compliance score theo thời gian
- Trend analysis
- Comparison giữa các hosts
- Compliance by category (Network, Authentication, etc.)

**Metrics:**
- Overall compliance percentage
- Pass/Fail/Skipped counts
- Critical/High/Medium/Low severity breakdown
- Historical trends

### 2.3. Alerting & Notifications

**Mô tả:**
- Email notifications cho:
  - Audit failures
  - Remediation failures
  - Critical findings
  - Scheduled audit results
- Webhook support cho integration với Slack, Teams, etc.

**Implementation:**
```python
# Backend notification service
class NotificationService:
    def send_email(self, to: str, subject: str, body: str)
    def send_webhook(self, url: str, payload: dict)
    def send_slack(self, channel: str, message: str)
```

### 2.4. Rule Management UI

**Mô tả:**
- UI để quản lý rules (CRUD)
- Import/export rules
- Rule testing interface
- Rule versioning

**Features:**
- Create/edit/delete rules
- Test rules trước khi deploy
- Rule templates
- Bulk import từ YAML

### 2.5. Host Groups & Tags

**Mô tả:**
- Group hosts theo environment (prod, staging, dev)
- Tag hosts (web-server, db-server, etc.)
- Apply rules theo group/tag
- Bulk operations

**Implementation:**
```python
# Backend
@app.post("/hosts/groups", dependencies=[RequireAdmin])
async def create_host_group(
    name: str = Form(...),
    hosts: List[str] = Form(...),
    tags: List[str] = Form(...),
):
    """Tạo host group."""
```

### 2.6. Audit Comparison

**Mô tả:**
- So sánh audit results giữa 2 thời điểm
- So sánh giữa các hosts
- Diff view cho changes

**UI:**
- Select 2 audits để compare
- Side-by-side comparison
- Highlight differences

### 2.7. Export Reports

**Mô tả:**
- Export audit reports ra PDF/Excel/CSV
- Customizable report templates
- Scheduled report generation

**Formats:**
- PDF (formatted reports)
- Excel (detailed data)
- CSV (for analysis)
- JSON (for API integration)

### 2.8. API Keys Management UI

**Mô tả:**
- UI để quản lý API keys
- Create/revoke/rotate keys
- Key usage tracking
- Expiration management

**Features:**
- List all API keys
- Create new keys với expiration
- Revoke keys
- View key usage stats

### 2.9. Activity Log

**Mô tả:**
- Audit log cho tất cả actions
- Track user activities
- Compliance logging

**Events to log:**
- User login/logout
- Audit runs
- Remediation actions
- User management
- Configuration changes

### 2.10. Multi-tenant Support

**Mô tả:**
- Support multiple organizations/tenants
- Data isolation
- Tenant-specific rules
- Tenant admin roles

---

## 🎨 3. UI/UX IMPROVEMENTS

### 3.1. Real-time Updates

**Mô tả:**
- WebSocket support cho real-time updates
- Live progress cho audit/remediation
- Real-time notifications

**Implementation:**
```python
# Backend: FastAPI WebSocket
@app.websocket("/ws/audit/{audit_id}")
async def audit_progress(websocket: WebSocket, audit_id: str):
    """WebSocket endpoint cho real-time audit progress."""
```

### 3.2. Advanced Filtering & Search

**Mô tả:**
- Advanced filters cho audits/remediations
- Full-text search
- Saved filters
- Export filtered results

**Filters:**
- By host
- By date range
- By status (PASS/FAIL/SKIPPED)
- By severity
- By rule category

### 3.3. Charts & Visualizations

**Mô tả:**
- Compliance trends chart
- Pass/Fail distribution pie chart
- Host comparison charts
- Timeline view

**Libraries:**
- Chart.js hoặc Recharts
- D3.js cho advanced visualizations

### 3.4. Dark Mode

**Mô tả:**
- Dark theme support
- User preference storage
- Smooth theme switching

### 3.5. Mobile Responsive

**Mô tả:**
- Optimize cho mobile devices
- Touch-friendly UI
- Mobile-specific features

---

## 🔒 4. SECURITY IMPROVEMENTS

### 4.1. Password Policy

**Mô tả:**
- Enforce password policy cho user accounts
- Password complexity requirements
- Password expiration
- Password history

### 4.2. Two-Factor Authentication (2FA)

**Mô tả:**
- TOTP-based 2FA
- SMS backup codes
- Recovery options

**Implementation:**
- Sử dụng `pyotp` library
- QR code generation
- Backup codes storage

### 4.3. Session Management

**Mô tả:**
- Session timeout
- Concurrent session limits
- Session activity tracking
- Force logout

### 4.4. Encryption at Rest

**Mô tả:**
- Encrypt sensitive data trong MongoDB
- Encrypt backups
- Key management

### 4.5. Audit Trail

**Mô tả:**
- Comprehensive audit logging
- Immutable logs
- Log retention policies
- Log analysis tools

---

## 📊 5. PERFORMANCE & SCALABILITY

### 5.1. Caching

**Mô tả:**
- Cache rules loading
- Cache host info
- Redis integration

### 5.2. Async Processing

**Mô tả:**
- Background tasks cho long-running operations
- Queue system cho audits
- Progress tracking

**Implementation:**
- Celery hoặc RQ
- Redis/RabbitMQ as message broker

### 5.3. Database Optimization

**Mô tả:**
- Index optimization
- Data archiving
- Partitioning large collections
- Query optimization

### 5.4. Connection Pooling

**Mô tả:**
- SSH connection pooling
- WinRM connection reuse
- Connection timeout management

---

## 🧪 6. TESTING & QUALITY

### 6.1. Unit Tests

**Mô tả:**
- Test coverage cho backend
- Mock SSH/WinRM connections
- Test remediation scripts

### 6.2. Integration Tests

**Mô tả:**
- End-to-end tests
- Test với real SSH/WinRM (test environment)
- API endpoint tests

### 6.3. Remediation Script Testing

**Mô tả:**
- Test framework cho remediation scripts
- Automated testing
- Safety checks

---

## 📚 7. DOCUMENTATION

### 7.1. API Documentation

**Mô tả:**
- Improve Swagger/OpenAPI docs
- Add examples
- Add error responses
- Add authentication info

### 7.2. User Guide

**Mô tả:**
- Step-by-step guides
- Video tutorials
- FAQ section
- Troubleshooting guide

### 7.3. Developer Guide

**Mô tả:**
- Architecture documentation
- How to add new rules
- How to create remediation scripts
- Contribution guidelines

---

## 🎯 8. PRIORITY RECOMMENDATIONS

### High Priority (Immediate)
1. ✅ **Chuẩn hóa Remediation Scripts** - Critical cho reliability
2. ✅ **Verification System** - Đảm bảo remediation thành công
3. ✅ **Scheduled Audits** - Core feature cho automation
4. ✅ **Compliance Dashboard** - Essential cho monitoring

### Medium Priority (Next Sprint)
5. **Alerting & Notifications** - Improve visibility
6. **Export Reports** - Business requirement
7. **Advanced Filtering** - Improve usability
8. **Activity Log** - Security & compliance

### Low Priority (Future)
9. **Multi-tenant Support** - Scale requirement
10. **2FA** - Enhanced security
11. **Real-time Updates** - Nice to have
12. **Mobile Responsive** - Accessibility

---

## 📝 9. REMEDIATION SCRIPT STANDARDS

### 9.1. Script Structure

```bash
#!/bin/bash
# ============================================================================
# Remediation Script: {rule_id}
# OS: {os_type}
# Description: {description}
# ============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script metadata
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="/tmp/${SCRIPT_NAME}.log"

# Load common functions
if [ -f "${SCRIPT_DIR}/_common_functions.sh" ]; then
    source "${SCRIPT_DIR}/_common_functions.sh"
else
    echo "ERROR: _common_functions.sh not found" >&2
    exit 1
fi

# ============================================================================
# Configuration
# ============================================================================
BACKUP_DIR="/tmp/remediation_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ============================================================================
# Functions
# ============================================================================

pre_check() {
    log_info "Running pre-check..."
    # Check if remediation is needed
    # Return 0 if needs remediation, 1 if already compliant
    return 0  # or 1
}

create_backup() {
    log_info "Creating backup..."
    # Backup current configuration
    # Return 0 on success
    return 0
}

remediate() {
    log_info "Applying remediation..."
    # Perform remediation
    # Return 0 on success
    return 0
}

verify() {
    log_info "Verifying remediation..."
    # Verify remediation was successful
    # Return 0 if compliant, 1 if still non-compliant
    return 0  # or 1
}

rollback() {
    log_error "Remediation failed, rolling back..."
    # Restore from backup
    # Return 0 on success
    return 0
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting remediation: ${SCRIPT_NAME}"
    
    # Pre-check
    if ! pre_check; then
        log_success "System already compliant, no remediation needed"
        exit 0
    fi
    
    # Create backup
    if ! create_backup; then
        log_error "Backup creation failed"
        exit 1
    fi
    
    # Apply remediation
    if ! remediate; then
        log_error "Remediation failed"
        rollback
        exit 1
    fi
    
    # Verify
    if ! verify; then
        log_error "Verification failed - remediation may not have worked"
        rollback
        exit 1
    fi
    
    log_success "Remediation completed successfully"
    exit 0
}

# Error handling
trap 'log_error "Script interrupted"; rollback; exit 1' INT TERM

# Run main
main "$@"
```

### 9.2. Common Functions Library

```bash
# _common_functions.sh

log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_FILE}" >&2
}

log_success() {
    echo "[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo "[WARNING] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "${LOG_FILE}"
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local backup="${BACKUP_DIR}/$(basename "$file").${TIMESTAMP}"
        cp "$file" "$backup"
        echo "$backup"
    fi
}

restore_file() {
    local backup="$1"
    if [ -f "$backup" ]; then
        local original="${backup%.*}"
        cp "$backup" "$original"
        return 0
    fi
    return 1
}
```

### 9.3. PowerShell Template (Windows)

```powershell
# Remediation Script Template for Windows
# Rule ID: {rule_id}
# OS: {os_type}

param(
    [switch]$DryRun = $false,
    [string]$LogFile = "C:\Temp\remediation.log"
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$Level] $timestamp - $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Host $logMessage
}

function Test-PreCheck {
    Write-Log "Running pre-check..."
    # Check if remediation is needed
    return $true  # or $false
}

function Backup-Configuration {
    Write-Log "Creating backup..."
    # Backup current configuration
    return $true
}

function Invoke-Remediation {
    Write-Log "Applying remediation..."
    if ($DryRun) {
        Write-Log "DRY RUN: Would apply remediation" -Level "INFO"
        return $true
    }
    # Perform remediation
    return $true
}

function Test-Verification {
    Write-Log "Verifying remediation..."
    # Verify remediation was successful
    return $true  # or $false
}

function Invoke-Rollback {
    Write-Log "Remediation failed, rolling back..." -Level "ERROR"
    # Restore from backup
    return $true
}

# Main execution
try {
    Write-Log "Starting remediation: $($MyInvocation.MyCommand.Name)"
    
    if (-not (Test-PreCheck)) {
        Write-Log "System already compliant, no remediation needed" -Level "SUCCESS"
        exit 0
    }
    
    if (-not (Backup-Configuration)) {
        Write-Log "Backup creation failed" -Level "ERROR"
        exit 1
    }
    
    if (-not (Invoke-Remediation)) {
        Write-Log "Remediation failed" -Level "ERROR"
        Invoke-Rollback
        exit 1
    }
    
    if (-not (Test-Verification)) {
        Write-Log "Verification failed" -Level "ERROR"
        Invoke-Rollback
        exit 1
    }
    
    Write-Log "Remediation completed successfully" -Level "SUCCESS"
    exit 0
}
catch {
    Write-Log "Unexpected error: $_" -Level "ERROR"
    Invoke-Rollback
    exit 1
}
```

---

## 🎬 10. IMPLEMENTATION ROADMAP

### Phase 1: Foundation (Weeks 1-2)
- [ ] Chuẩn hóa remediation scripts
- [ ] Tạo common functions library
- [ ] Implement verification system
- [ ] Improve error handling

### Phase 2: Core Features (Weeks 3-4)
- [ ] Scheduled audits
- [ ] Compliance dashboard
- [ ] Export reports
- [ ] Activity log

### Phase 3: Enhancements (Weeks 5-6)
- [ ] Alerting & notifications
- [ ] Advanced filtering
- [ ] Charts & visualizations
- [ ] Rule management UI

### Phase 4: Advanced (Weeks 7-8)
- [ ] Multi-tenant support
- [ ] 2FA
- [ ] Real-time updates
- [ ] Performance optimization

---

## 📞 Notes

- Tất cả các đề xuất đều có thể implement từng phần
- Ưu tiên theo business requirements
- Có thể adjust roadmap dựa trên feedback
- Document này sẽ được update khi có thay đổi


