# Remediation Scripts Safety Guidelines

## ⚠️ Vấn đề đã được xử lý

Tất cả remediation scripts đã được cải thiện để tránh **treo hệ thống**:

### 1. **Timeout cho tất cả operations**

| Operation | Timeout | Lý do |
|-----------|---------|-------|
| `apt-get` commands | 60-120s | Có thể chậm khi download packages |
| `systemctl` commands | 30s | Có thể hang nếu service có vấn đề |
| `mount` commands | 30s | Có thể hang nếu filesystem busy |
| `update-grub` | 180s | Có thể rất lâu trên một số hệ thống |
| SSH execution | 300s (5 phút) | Timeout tổng thể cho toàn bộ script |

### 2. **Apt Lock Checking**

Tất cả scripts có `apt-get` đều:
- ✅ Check và wait cho apt lock (max 30s)
- ✅ Tránh conflict với các apt processes khác
- ✅ Fallback force remove nếu timeout

### 3. **Non-Interactive Mode**

- ✅ `DEBIAN_FRONTEND=noninteractive` để tránh prompts
- ✅ Tất cả commands đều có `-y` flag

### 4. **Error Handling**

- ✅ `set -euo pipefail` để bắt lỗi sớm
- ✅ Fallback operations nếu timeout
- ✅ Graceful degradation (không crash hệ thống)

---

## 📋 Checklist Safety cho Scripts Mới

Khi tạo script remediation mới, đảm bảo:

```bash
#!/bin/bash
set -euo pipefail

# ✅ 1. Set non-interactive
export DEBIAN_FRONTEND=noninteractive

# ✅ 2. Wait for apt lock (nếu dùng apt-get)
wait_for_apt() {
    # ... (xem _common_functions.sh)
}

# ✅ 3. Timeout cho mọi command nguy hiểm
timeout 60 apt-get remove -y package
timeout 30 systemctl stop service
timeout 30 mount -o remount,options /path

# ✅ 4. Fallback nếu timeout
timeout 60 command || {
    echo "⚠️ Timeout, trying fallback"
    fallback_command
}
```

---

## 🔍 Scripts đã được cải thiện

### **Filesystem (7 scripts):**
- ✅ `cis-1.1.2-nodev-tmp.sh` - Timeout cho mount
- ✅ `cis-1.1.3-nosuid-tmp.sh` - Timeout cho mount
- ✅ `cis-1.1.8-nodev-var-tmp.sh` - Timeout cho mount
- ✅ `cis-1.1.9-nosuid-var-tmp.sh` - Timeout cho mount
- ✅ `cis-1.1.10-noexec-var-tmp.sh` - Timeout cho mount
- ✅ `cis-1.4.1-bootloader-permissions.sh` - Safe
- ✅ `cis-1.7.1-motd-permissions.sh` - Safe

### **Services (7 scripts):**
- ✅ `cis-2.1.1-xinetd-disabled.sh` - Apt lock + timeout
- ✅ `cis-2.2.1-x11-disabled.sh` - Apt lock + timeout
- ✅ `cis-2.2.2-avahi-disabled.sh` - Systemctl + apt lock + timeout
- ✅ `cis-2.2.3-cups-disabled.sh` - Systemctl + apt lock + timeout
- ✅ `cis-2.2.4-dhcp-disabled.sh` - Systemctl + apt lock + timeout
- ✅ `cis-2.2.5-ldap-disabled.sh` - Systemctl + apt lock + timeout
- ✅ `cis-2.2.6-nfs-disabled.sh` - Systemctl + apt lock + timeout
- ✅ `cis-2.2.7-rpcbind-disabled.sh` - Systemctl + apt lock + timeout

### **Network (10 scripts):**
- ✅ Tất cả đều safe (chỉ sysctl, không blocking)

### **Logging (3 scripts):**
- ✅ `cis-4.1.1-auditd-installed.sh` - Apt lock + timeout
- ✅ `cis-4.1.2-auditd-enabled.sh` - Apt lock + systemctl timeout
- ✅ `cis-4.1.3-audit-rules-permanent.sh` - update-grub timeout

### **SSH (6 scripts):**
- ✅ Tất cả đều có systemctl reload timeout

---

## 🚨 Operations Nguy Hiểm (Đã xử lý)

| Operation | Risk | Solution |
|-----------|------|----------|
| `apt-get` | Chờ lock, download lâu | ✅ Timeout + lock check |
| `systemctl stop/start` | Hang nếu service stuck | ✅ Timeout 30s |
| `mount remount` | Hang nếu filesystem busy | ✅ Timeout 30s |
| `update-grub` | Rất lâu trên một số hệ thống | ✅ Timeout 180s |
| SSH execution | Hang nếu network issue | ✅ Timeout 300s ở Python level |

---

## ✅ Kết quả

- ✅ **34 scripts** đã được cải thiện
- ✅ **0 blocking operations** không có timeout
- ✅ **100% scripts** có error handling
- ✅ **Tất cả apt-get** có lock checking

**Hệ thống sẽ không bị treo** ngay cả khi:
- apt-get đang chạy process khác
- Service bị stuck
- Network timeout
- Filesystem busy

