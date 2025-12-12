# Troubleshooting Dashboard

## Lỗi: ERR_CONNECTION_REFUSED

Lỗi này có nghĩa là dashboard không thể kết nối đến backend API.

### Nguyên nhân và giải pháp:

#### 1. Backend chưa chạy

**Kiểm tra:**
```bash
# Kiểm tra backend có đang chạy không
curl http://localhost:8080/healthz

# Hoặc
ps aux | grep uvicorn
```

**Giải pháp:**
```bash
# Khởi động backend
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8080
```

#### 2. Backend chạy trên port khác

**Kiểm tra:**
```bash
# Xem port nào đang được sử dụng
netstat -tulpn | grep 8080
# hoặc
lsof -i :8080
```

**Giải pháp:**
- Nếu backend chạy trên port khác (ví dụ 8000), tạo file `.env` trong `dashboard/`:
```env
VITE_API_URL=http://localhost:8000
```

#### 3. Backend chạy trên server khác

**Giải pháp:**
Tạo file `dashboard/.env`:
```env
VITE_API_URL=http://your-server-ip:8080
```

Sau đó rebuild:
```bash
cd dashboard
npm run build
```

#### 4. Firewall chặn kết nối

**Kiểm tra:**
```bash
# Test từ máy khác
curl http://your-server-ip:8080/healthz
```

**Giải pháp:**
```bash
# Mở port 8080
sudo ufw allow 8080/tcp
# hoặc
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

---

## Lỗi: Invalid API key

### Nguyên nhân:

1. **API key không đúng format**
   - Phải bắt đầu với `sk_`
   - Phải copy đầy đủ (không thiếu ký tự)

2. **API key chưa được tạo**
   - Cần tạo API key đầu tiên qua `/auth/setup`

3. **API key đã bị revoke hoặc expired**

### Giải pháp:

#### Tạo API key mới:

```bash
# Tạo API key đầu tiên (không cần auth)
curl -X POST "http://localhost:8080/auth/setup" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Dashboard Key"

# Response sẽ có:
# {
#   "api_key": "sk_...",
#   "warning": "⚠️ Lưu API key này ngay!..."
# }
```

#### Test API key:

```bash
# Test với API key
curl -X GET "http://localhost:8080/reports/compliance-stats" \
  -H "X-API-Key: sk_YOUR_KEY_HERE"
```

---

## Lỗi: CORS Error

Nếu thấy lỗi CORS trong browser console, backend đã có CORS middleware nhưng có thể cần config thêm.

**Kiểm tra:**
- Xem browser console (F12) có lỗi CORS không
- Kiểm tra Network tab xem request có bị block không

**Giải pháp:**
Backend đã có CORS middleware, nếu vẫn lỗi, kiểm tra:
1. Backend có restart sau khi thêm CORS không?
2. Có đang dùng HTTPS trong khi backend là HTTP không?

---

## Debug Steps

### 1. Kiểm tra Backend

```bash
# Test health check
curl http://localhost:8080/healthz
# Expected: {"status":"ok"}

# Test API info
curl http://localhost:8080/api/info
# Expected: JSON với thông tin API
```

### 2. Kiểm tra Dashboard Build

```bash
# Kiểm tra build có tồn tại
ls -la dashboard/dist/

# Kiểm tra index.html
cat dashboard/dist/index.html | head -20
```

### 3. Kiểm tra Browser Console

1. Mở browser (F12)
2. Vào tab **Console**
3. Xem có lỗi gì không
4. Vào tab **Network**
5. Thử login lại
6. Xem request nào fail

### 4. Kiểm tra API URL

Trong browser console, chạy:
```javascript
// Xem API URL đang dùng
console.log('API URL:', import.meta.env.VITE_API_URL || 'http://localhost:8080')
```

---

## Common Issues

### Issue: Dashboard hiển thị nhưng không load data

**Nguyên nhân:** API key không hợp lệ hoặc backend không trả về data

**Giải pháp:**
1. Kiểm tra API key trong localStorage:
   ```javascript
   // Trong browser console
   localStorage.getItem('api_key')
   ```
2. Test API key với curl
3. Xem Network tab để xem request nào fail

### Issue: Dashboard không hiển thị (blank page)

**Nguyên nhân:** 
- Build không đúng
- JavaScript error

**Giểm tra:**
1. Browser console có lỗi JavaScript không?
2. Build lại dashboard:
   ```bash
   cd dashboard
   rm -rf dist node_modules
   npm install
   npm run build
   ```

### Issue: Login thành công nhưng redirect về login

**Nguyên nhân:** 
- Authentication state không được lưu đúng
- ProtectedRoute check fail

**Giải pháp:**
1. Xem browser console
2. Kiểm tra localStorage có API key không
3. Clear cache và thử lại

---

## Quick Fixes

### Reset hoàn toàn

```bash
# 1. Clear browser cache và localStorage
# Trong browser console:
localStorage.clear()
location.reload()

# 2. Rebuild dashboard
cd dashboard
rm -rf dist
npm run build

# 3. Restart backend
cd backend
# Kill existing process
pkill -f uvicorn
# Start again
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8080
```

### Test từ đầu

```bash
# 1. Test backend
curl http://localhost:8080/healthz

# 2. Tạo API key
curl -X POST "http://localhost:8080/auth/setup" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test Key"

# 3. Test API key
curl -X GET "http://localhost:8080/reports/compliance-stats" \
  -H "X-API-Key: sk_YOUR_KEY"

# 4. Truy cập dashboard
# http://localhost:8080
```

---

## Still Having Issues?

1. **Check logs:**
   - Backend logs (terminal nơi chạy uvicorn)
   - Browser console (F12)
   - Network tab (F12 → Network)

2. **Verify setup:**
   - MongoDB đang chạy?
   - Backend kết nối được MongoDB?
   - Port 8080 có bị block không?

3. **Test từng bước:**
   - Backend health check
   - API key creation
   - API key verification
   - Dashboard access

