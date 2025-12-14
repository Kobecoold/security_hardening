# 🚀 Quick Start Guide

Hướng dẫn nhanh để chạy toàn bộ Security Hardening project.

## 📋 Yêu cầu

- **Python 3.9+** (cho Backend)
- **Node.js 18+** và **npm** (cho Dashboard)
- **Docker** và **Docker Compose** (cho MongoDB)
- **Git** (để clone project)

---

## 🐧 Linux / macOS

### Cách 1: Sử dụng script tự động (Khuyến nghị)

```bash
# Cấp quyền thực thi
chmod +x start.sh stop.sh

# Khởi động toàn bộ project
./start.sh

# Dừng toàn bộ project
./stop.sh
```

### Cách 2: Chạy thủ công từng service

#### Bước 1: Khởi động MongoDB
```bash
docker-compose up -d mongodb
```

#### Bước 2: Khởi động Backend API
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

#### Bước 3: Khởi động Dashboard (terminal mới)
```bash
cd dashboard
npm install
npm run dev
```

---

## 🪟 Windows

### Cách 1: Sử dụng PowerShell script

```powershell
# Chạy script
.\start.ps1
```

### Cách 2: Chạy thủ công từng service

#### Bước 1: Khởi động MongoDB
```powershell
docker-compose up -d mongodb
```

#### Bước 2: Khởi động Backend API
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

#### Bước 3: Khởi động Dashboard (PowerShell mới)
```powershell
cd dashboard
npm install
npm run dev
```

---

## 🌐 Truy cập Services

Sau khi khởi động, truy cập:

- **Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8080
- **API Documentation**: http://localhost:8080/docs
- **MongoDB**: localhost:27017

---

## 🔐 Tạo API Key đầu tiên

1. Truy cập http://localhost:8080/docs
2. Tìm endpoint `/auth/setup`
3. Click "Try it out" và submit (không cần nhập gì)
4. Copy API key được trả về
5. Dùng API key này để đăng nhập vào Dashboard

Hoặc dùng curl:

```bash
curl -X POST "http://localhost:8080/auth/setup" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Default Key"
```

---

## 🛑 Dừng Services

### Linux/macOS:
```bash
./stop.sh
```

### Windows:
- Đóng các terminal windows đang chạy services
- Hoặc dùng Task Manager để kill processes

### Dừng MongoDB:
```bash
docker-compose stop mongodb
```

---

## 🐛 Troubleshooting

### Port đã được sử dụng

**Port 8080 (Backend) đã được dùng:**
```bash
# Linux/macOS
lsof -ti:8080 | xargs kill -9

# Windows PowerShell
Get-Process -Id (Get-NetTCPConnection -LocalPort 8080).OwningProcess | Stop-Process
```

**Port 3000 (Dashboard) đã được dùng:**
```bash
# Linux/macOS
lsof -ti:3000 | xargs kill -9

# Windows PowerShell
Get-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess | Stop-Process
```

### MongoDB không khởi động

```bash
# Kiểm tra Docker
docker ps

# Xem logs
docker-compose logs mongodb

# Khởi động lại
docker-compose restart mongodb
```

### Backend không kết nối MongoDB

- Đảm bảo MongoDB container đang chạy: `docker ps | grep mongodb`
- Kiểm tra connection: `docker-compose exec mongodb mongosh --eval "db.runCommand('ping')"`

### Dashboard không kết nối Backend

- Kiểm tra Backend đang chạy: http://localhost:8080/healthz
- Kiểm tra file `dashboard/.env` có `VITE_API_URL=http://localhost:8080`

---

## 📝 Development vs Production

### Development (hiện tại)
- Dashboard chạy trên port 3000 (Vite dev server)
- Backend chạy trên port 8080
- Hot reload enabled

### Production
1. Build Dashboard:
   ```bash
   cd dashboard
   npm run build
   ```
2. Backend sẽ tự động serve Dashboard từ `dashboard/dist/`
3. Chỉ cần truy cập http://localhost:8080

---

## 🔄 Cập nhật Dependencies

### Backend:
```bash
cd backend
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt --upgrade
```

### Dashboard:
```bash
cd dashboard
npm update
```

---

## 📚 Tài liệu thêm

- [README.md](README.md) - Hướng dẫn chi tiết
- [ARCHITECTURE.md](ARCHITECTURE.md) - Kiến trúc hệ thống
- [dashboard/README.md](dashboard/README.md) - Dashboard documentation

---

## 💡 Tips

1. **Giữ MongoDB chạy**: MongoDB có thể chạy liên tục, không cần restart mỗi lần
2. **API Key**: Lưu API key an toàn, dùng cho tất cả requests
3. **Logs**: Xem logs backend trong terminal, logs MongoDB: `docker-compose logs mongodb`
4. **Hot Reload**: Dashboard và Backend đều có hot reload trong development mode

---

## ✅ Checklist

- [ ] Docker đã cài đặt và chạy
- [ ] Python 3.9+ đã cài đặt
- [ ] Node.js 18+ đã cài đặt
- [ ] MongoDB container đang chạy
- [ ] Backend API đang chạy (port 8080)
- [ ] Dashboard đang chạy (port 3000)
- [ ] Đã tạo API key đầu tiên
- [ ] Có thể truy cập Dashboard và đăng nhập

---

**Chúc bạn sử dụng thành công! 🎉**

