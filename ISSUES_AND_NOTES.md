# 🔍 Security Hardening - Issues & Notes

## ⚠️ Critical Issues

### 1. Rollback Logic Không Hỗ Trợ Batch Backups (`rule_ids`)

**Vấn đề:**
- Khi tạo backup cho nhiều rules, backup lưu `rule_ids: [list]` và `rule_id: None`
- Nhưng logic rollback chỉ tìm theo `rule_id` (single), không tìm theo `rule_ids` (list)
- **Hậu quả:** Rollback sẽ không tìm thấy batch backups!

**Files bị ảnh hưởng:**
- `backend/windows_rollback.py` - `execute_rollback()` method (line 726-753)
- `backend/linux_rollback.py` - `execute_rollback()` method (cần kiểm tra)

**Cần sửa:**
```python
# Hiện tại (chỉ tìm theo rule_id):
backup = self.db.backups.find_one({
    "host": host, 
    "rule_id": rule_id,  # ❌ Không tìm thấy batch backups
    ...
})

# Cần sửa thành:
query = {"host": host, "type": "pre_remediation_backup", "os_type": "windows"}
if rule_id:
    query["$or"] = [
        {"rule_id": rule_id},  # Single rule backup
        {"rule_ids": rule_id}   # Batch backup chứa rule này
    ]
backup = self.db.backups.find_one(query, sort=[("timestamp", -1)])
```

---

### 2. API Endpoint `/backups/windows/rule/{rule_id}` Không Hỗ Trợ `rule_ids`

**Vấn đề:**
- Endpoint này chỉ query theo `rule_id`, không tìm batch backups có `rule_ids` chứa rule đó
- Frontend có thể không hiển thị batch backups đúng cách

**File:** `backend/main.py` line 1042-1069

**Cần sửa:**
```python
query = {
    "os_type": "windows",
    "type": "pre_remediation_backup",
    "$or": [
        {"rule_id": rule_id},
        {"rule_ids": rule_id}  # Tìm trong list
    ]
}
```

---

## 🔒 Security Issues

### 3. CORS Configuration Quá Mở

**File:** `backend/main.py` line 45-50

**Vấn đề:**
```python
allow_origins=["*"],  # ❌ Quá mở, không an toàn cho production
```

**Khuyến nghị:**
```python
allow_origins=[
    "http://localhost:5173",  # Dev
    "http://localhost:3000",  # Dev alternative
    "https://yourdomain.com"  # Production
],
```

---

### 4. API Key Mapping Chưa Implement

**File:** `backend/main.py` line 1927

**Vấn đề:**
```python
# Note: Cần implement logic để map API key với user
```

**Khuyến nghị:** Implement mapping giữa API key và user để:
- Track user activity
- Audit logs
- User-specific permissions

---

## 🐛 Potential Bugs

### 5. Rollback Page Có Thể Không Hiển Thị Batch Backups

**File:** `dashboard/src/pages/Rollback.jsx`

**Vấn đề:** Frontend có thể filter backups theo `rule_id` nhưng không xử lý `rule_ids` (list)

**Cần kiểm tra:** Logic filter và display backups

---

### 6. Error Handling - Silent Failures

**Vấn đề:** Nhiều nơi catch exception nhưng chỉ log, không raise:
- Backup creation failures (non-critical)
- Connection errors
- File read errors

**Khuyến nghị:** 
- Log đầy đủ errors
- Return status rõ ràng cho frontend
- User notifications cho critical errors

---

### 7. Connection Pooling Chưa Có

**Vấn đề:**
- Mỗi request tạo connection mới (SSH/WinRM)
- Không reuse connections
- Có thể chậm với nhiều requests

**Khuyến nghị:** Implement connection pooling hoặc connection reuse

---

## 📝 Code Quality Issues

### 8. Inconsistent Error Messages

**Vấn đề:** Error messages không thống nhất:
- Một số dùng tiếng Việt
- Một số dùng tiếng Anh
- Format không đồng nhất

**Khuyến nghị:** Standardize error messages

---

### 9. Hardcoded Values

**Vấn đề:**
- Timeout values hardcoded
- File paths hardcoded
- Magic numbers

**Khuyến nghị:** Move to config file

---

### 10. Missing Type Hints

**Vấn đề:** Một số functions thiếu type hints

**Khuyến nghị:** Add type hints cho tất cả functions

---

## 🔄 Logic Issues

### 11. Batch Backup Query Logic

**Vấn đề:** Khi query backups:
- Chỉ tìm theo `rule_id` (single)
- Không tìm theo `rule_ids` (list)
- Không có logic để tìm backup chứa rule cụ thể trong list

**Cần sửa ở:**
- `backend/windows_rollback.py` - `execute_rollback()`
- `backend/linux_rollback.py` - `execute_rollback()` (nếu có)
- `backend/main.py` - `/backups/windows/rule/{rule_id}`
- `backend/main.py` - `/backups/linux/rule/{rule_id}` (nếu có)

---

### 12. Backup ID Generation Có Thể Trùng

**Vấn đề:**
```python
backup_id = f"backup_{int(datetime.utcnow().timestamp())}"
```

Nếu tạo backup cùng lúc (same second) có thể trùng ID.

**Khuyến nghị:** Thêm random suffix hoặc dùng MongoDB ObjectId

---

## 🎯 Recommendations

### High Priority (Fix Immediately)
1. ✅ **Fix rollback logic để hỗ trợ `rule_ids`** - Critical bug
2. ✅ **Fix API endpoints để query batch backups** - Critical bug
3. ✅ **CORS configuration** - Security issue

### Medium Priority (Next Sprint)
4. **Implement API key mapping**
5. **Improve error handling**
6. **Connection pooling**

### Low Priority (Future)
7. **Standardize error messages**
8. **Move hardcoded values to config**
9. **Add type hints**
10. **Improve backup ID generation**

---

## 📋 Testing Checklist

- [ ] Test rollback với single rule backup
- [ ] Test rollback với batch backup (multiple rules)
- [ ] Test rollback tìm backup theo rule_id trong batch backup
- [ ] Test API endpoints với batch backups
- [ ] Test frontend hiển thị batch backups
- [ ] Test CORS với production origins
- [ ] Test error handling scenarios
- [ ] Test connection reuse/pooling

---

## 🔗 Related Files

- `backend/windows_rollback.py` - Rollback logic
- `backend/linux_rollback.py` - Rollback logic  
- `backend/main.py` - API endpoints
- `dashboard/src/pages/Rollback.jsx` - Frontend rollback page
- `dashboard/src/pages/Backups.jsx` - Frontend backups list

---

*Generated: 2025-01-XX*
*Last Updated: After batch backup implementation*
