# Backup Scope Documentation

## ⚠️ QUAN TRỌNG: Backup KHÔNG phải full system backup

### 🔍 Backup đang làm gì?

Backup **CHỈ** backup những file cấu hình nhỏ và an toàn, **KHÔNG** backup toàn bộ hệ thống:

#### **Linux Backup:**
- ✅ `/etc/ssh/sshd_config` - SSH configuration (max 100KB)
- ✅ `/etc/passwd` - User accounts (max 50KB)
- ✅ `/etc/group` - Group information (max 50KB)
- ✅ SSH service status

**KHÔNG backup:**
- ❌ `/etc/shadow` - Quá nguy hiểm, có thể hang
- ❌ `/etc/sudoers` - Quá nguy hiểm, có thể hang
- ❌ Toàn bộ filesystem
- ❌ Applications
- ❌ User data

#### **Windows Backup:**
- ✅ Password policy settings
- ✅ Remote assistance setting
- ✅ Administrator account status
- ✅ Audit policy

**KHÔNG backup:**
- ❌ Registry toàn bộ
- ❌ System files
- ❌ User data
- ❌ Applications

---

## 🛡️ Safety Features

### 1. **Timeout cho mỗi operation:**
- SSH config: 15s timeout
- File backup: 15s timeout per file
- Service status: 10s timeout

### 2. **Giới hạn kích thước:**
- SSH config: Max 100KB
- Other files: Max 50KB
- Tránh backup file quá lớn

### 3. **Skip nếu timeout:**
- Nếu một file timeout, skip và tiếp tục
- Không block toàn bộ backup process

### 4. **Chỉ backup file an toàn:**
- Không backup `/etc/shadow` (có thể hang)
- Không backup `/etc/sudoers` (có thể hang)
- Chỉ backup file nhỏ và đọc nhanh

---

## 📋 Mục đích của Backup

Backup này **CHỈ** để:
- ✅ Rollback các thay đổi SSH configuration
- ✅ Rollback các thay đổi user/group (nếu có)
- ✅ Khôi phục service status

**KHÔNG** để:
- ❌ Khôi phục toàn bộ hệ thống
- ❌ Disaster recovery
- ❌ Full system restore

---

## ⚠️ Lưu ý

1. **Backup này KHÔNG thay thế full system backup**
2. **Nếu cần full backup, dùng tools chuyên dụng:**
   - Linux: `tar`, `rsync`, `borgbackup`, `restic`
   - Windows: Windows Backup, VSS, System Restore

3. **Backup này chỉ dùng cho rollback remediation changes**

---

## 🔧 Cải thiện đã thực hiện

- ✅ Thêm timeout cho tất cả backup operations
- ✅ Giới hạn kích thước file backup
- ✅ Skip các file nguy hiểm (`/etc/shadow`, `/etc/sudoers`)
- ✅ Non-blocking: Nếu một file fail, tiếp tục với file khác
- ✅ Fast: Chỉ backup những gì cần thiết

**Backup sẽ không bị treo nữa!** ⚡

