# Kiến trúc Hệ thống Security Hardening

## 📊 Tổng quan Kiến trúc

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT (Browser/API)                      │
│                    (Dashboard/Postman/curl)                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ HTTP/HTTPS (Port 8080)
                       │ X-API-Key Header
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              FastAPI Backend (Python)                        │
│              Chạy trên HOST (không containerize)            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  main.py (API Endpoints)                              │   │
│  │  - /audit/linux, /audit/windows                      │   │
│  │  - /remediate/linux, /remediate/windows             │   │
│  │  - /rollback/linux, /rollback/windows               │   │
│  │  - /reports/*                                        │   │
│  │  - /auth/api-keys                                    │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Authentication (auth.py)                            │   │
│  │  - Verify API Keys                                   │   │
│  │  - Track usage                                       │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ MongoDB Connection
                       │ (mongodb://localhost:27017)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              MongoDB Container (Docker)                      │
│              Container: security_hardening_mongodb           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Collections:                                        │   │
│  │  - audit_reports      (Kết quả audit)               │   │
│  │  - remediation_logs   (Log remediation)            │   │
│  │  - system_backups     (Backups trước remediation)   │   │
│  │  - api_keys           (API keys & usage)            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                       │
                       │ SSH (Linux) / WinRM (Windows)
                       │
        ┌──────────────┴──────────────┐
        │                              │
        ▼                              ▼
┌───────────────┐            ┌───────────────┐
│  Linux Hosts  │            │ Windows Hosts │
│  (SSH)        │            │  (WinRM)      │
│               │            │               │
│  - Ubuntu     │            │  - Windows 10 │
│  - Debian     │            │  - Windows 11 │
└───────────────┘            └───────────────┘
```

## 🔄 Luồng hoạt động

### 1. **Khởi động Hệ thống**

```bash
# Bước 1: Khởi động MongoDB container
docker compose up -d mongodb
# → 1 container chạy: security_hardening_mongodb

# Bước 2: Khởi động FastAPI Backend
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8080
# → 1 process Python chạy trên host (không phải container)
```

**Kết quả:**
- ✅ **1 Docker container**: MongoDB
- ✅ **1 Python process**: FastAPI Backend
- ✅ **Tổng cộng**: 1 container + 1 process

### 2. **Luồng Audit Linux**

```
User → API Request (với X-API-Key)
  ↓
FastAPI Backend:
  1. Verify API Key (auth.py)
  2. Kết nối SSH đến Linux host
  3. Auto-detect OS (Ubuntu 20.04, Debian 12...)
  4. Load rules từ content/rules/{os}/
  5. Chạy từng rule check (bash scripts)
  6. Lưu kết quả vào MongoDB (audit_reports)
  7. Trả về JSON response
```

### 3. **Luồng Audit Windows**

```
User → API Request (với X-API-Key)
  ↓
FastAPI Backend:
  1. Verify API Key
  2. Kết nối WinRM đến Windows host
  3. Auto-detect OS (Windows 10, Windows 11...)
  4. Load rules từ content/rules/{os}/
  5. Chạy từng rule check (WinRM commands)
  6. Lưu kết quả vào MongoDB (audit_reports)
  7. Trả về JSON response
```

### 4. **Luồng Remediation**

```
User → POST /remediate/{linux|windows}
  ↓
FastAPI Backend:
  1. Verify API Key
  2. Tạo backup (lưu vào MongoDB system_backups)
  3. Load remediation script từ scripts/remediation/
  4. Chạy script trên target host (SSH/WinRM)
  5. Lưu log vào MongoDB (remediation_logs)
  6. Trả về kết quả
```

### 5. **Luồng Rollback**

```
User → POST /rollback/{linux|windows}
  ↓
FastAPI Backend:
  1. Verify API Key
  2. Lấy backup từ MongoDB (system_backups)
  3. Khôi phục cấu hình từ backup
  4. Lưu rollback log vào MongoDB
  5. Trả về kết quả
```

## 🏗️ Kiến trúc hiện tại

### **Services/Containers:**

| Service | Type | Port | Status |
|---------|------|------|--------|
| **MongoDB** | Docker Container | 27017 | ✅ Containerized |
| **FastAPI Backend** | Python Process | 8080 | ⚠️ Chạy trên host |
| **Dashboard** | - | - | ❌ Chưa có |

### **Tại sao FastAPI không containerize?**

**Hiện tại:**
- FastAPI chạy trực tiếp trên host vì:
  - Cần truy cập SSH keys từ host
  - Cần network access đến target hosts
  - Đơn giản hóa development

**Có thể containerize nếu:**
- Mount SSH keys vào container
- Sử dụng Docker network
- Cần scale horizontal

## 🚀 Đề xuất Cải thiện

### **Option 1: Full Containerized (Recommended cho Production)**

```yaml
# docker-compose.yml (mở rộng)
services:
  mongodb:
    # ... existing ...
  
  backend:
    build: ./backend
    ports:
      - "8080:8080"
    volumes:
      - ./content:/app/content
      - ./scripts:/app/scripts
      - ~/.ssh:/root/.ssh:ro  # Mount SSH keys
    depends_on:
      - mongodb
    environment:
      - MONGODB_URL=mongodb://mongodb:27017/
  
  dashboard:
    build: ./dashboard
    ports:
      - "3000:3000"
    depends_on:
      - backend
```

**Kết quả:** 3 containers chạy cùng lúc

### **Option 2: Hybrid (Hiện tại - Đơn giản)**

```
✅ MongoDB: Container
✅ FastAPI: Host process
✅ Dashboard: Static files (sẽ tạo)
```

**Kết quả:** 1 container + 1-2 processes

## 📝 Tóm tắt

**Hiện tại khi chạy:**
- ✅ **1 container**: MongoDB
- ✅ **1 process**: FastAPI Backend
- ❌ **0 container/process**: Dashboard (chưa có)

**Sau khi thêm Dashboard:**
- ✅ **1 container**: MongoDB
- ✅ **1 process**: FastAPI Backend
- ✅ **1 static server**: Dashboard (có thể serve từ FastAPI hoặc nginx)

**Tổng cộng:** 1 container + 1-2 processes (không phải nhiều containers)

