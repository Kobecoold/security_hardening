# Security Hardening Agentless (Python)

## Overview
- **Backend Python (FastAPI)**: API kiểm tra máy chủ Linux/Windows từ xa qua SSH/WinRM
- **Agentless**: Không cần cài đặt agent trên các máy client
- **Database**: MongoDB để lưu trữ audit reports, remediation logs, và backups
- **Rule-based**: Lưu rule/scripts dạng YAML + Bash/Python/PowerShell (content/rules)

### Tree Structure
```
security_hardening/
├── backend/                 # Python FastAPI server
│   ├── main.py             # API endpoints
│   ├── database.py         # MongoDB connection
│   ├── linux_audit.py      # Linux SSH audit
│   ├── windows_audit.py    # Windows WinRM audit
│   ├── linux_rollback.py   # Linux backup/rollback
│   ├── rollback.py         # Windows backup/rollback
│   └── utils.py            # Utilities
├── content/
│   └── rules/              # Security rules YAML
│       ├── ubuntu-20.04/
│       ├── ubuntu-22.04/
│       ├── debian-12/
│       └── windows-11/
├── scripts/
│   └── remediation/        # Remediation scripts
│       ├── ubuntu-20.04/
│       └── windows-10/
├── docker-compose.yml      # MongoDB Docker setup
└── README.md
```

---

## Yêu cầu Hệ thống

### Server Requirements (Linux)
- **OS**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / RHEL 8+
- **Python**: 3.9 hoặc cao hơn
- **RAM**: Tối thiểu 2GB (khuyến nghị 4GB+)
- **Disk**: Tối thiểu 10GB (khuyến nghị 20GB+)
- **Network**: Kết nối mạng đến các máy client cần audit

### Dependencies
- Docker và Docker Compose (để chạy MongoDB)
- hoặc MongoDB cài đặt trực tiếp trên server

---

## Hướng dẫn Triển khai trên Linux Server

### Bước 1: Chuẩn bị Server

#### 1.1. Cập nhật hệ thống
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/RHEL
sudo yum update -y
```

#### 1.2. Cài đặt Python 3.9+
```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip python3-venv -y

# CentOS/RHEL 8+
sudo dnf install python39 python39-pip -y
```

#### 1.3. Cài đặt Docker và Docker Compose
```bash
# Cài đặt Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Cài đặt Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Đăng xuất và đăng nhập lại để áp dụng group docker
# Hoặc chạy: newgrp docker
```

### Bước 2: Clone/Upload Project

#### 2.1. Clone từ Git (nếu có repository)
```bash
git clone <repository-url> security_hardening
cd security_hardening
```

#### 2.2. Hoặc upload project lên server
```bash
# Sử dụng SCP từ máy local
scp -r security_hardening/ user@your-server:/opt/

# Hoặc sử dụng SFTP, rsync, etc.
```

### Bước 3: Setup MongoDB với Docker

#### 3.1. Khởi động MongoDB container
```bash
# Từ thư mục project root
docker compose up -d mongodb
```

#### 3.2. Kiểm tra MongoDB đã chạy
```bash
# Kiểm tra container
docker ps | grep mongodb

# Kiểm tra logs
docker compose logs mongodb

# Test connection
docker compose exec mongodb mongosh --eval "db.runCommand('ping')"
```

MongoDB sẽ chạy trên port **27017** và dữ liệu được lưu trong Docker volumes.

### Bước 4: Setup Python Environment

#### 4.1. Tạo virtual environment
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

#### 4.2. Cài đặt dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Bước 5: Chạy Application

#### 5.1. Chạy trực tiếp (Development)
```bash
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8080
```

#### 5.2. Chạy với systemd service (Production - Khuyến nghị)

Tạo systemd service file:
```bash
sudo nano /etc/systemd/system/security-hardening.service
```

Nội dung service file:
```ini
[Unit]
Description=Security Hardening Agentless API
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=your-username
Group=your-group
WorkingDirectory=/opt/security_hardening/backend
Environment="PATH=/opt/security_hardening/backend/.venv/bin"
ExecStart=/opt/security_hardening/backend/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=security-hardening

[Install]
WantedBy=multi-user.target
```

**Lưu ý**: Thay `your-username`, `your-group`, và đường dẫn `/opt/security_hardening` cho phù hợp với hệ thống của bạn.

Khởi động service:
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service để tự khởi động khi reboot
sudo systemctl enable security-hardening

# Start service
sudo systemctl start security-hardening

# Kiểm tra status
sudo systemctl status security-hardening

# Xem logs
sudo journalctl -u security-hardening -f
```

### Bước 6: Kiểm tra Application

#### 6.1. Test API Health Check
```bash
curl http://localhost:8080/healthz
# Kết quả mong đợi: {"status":"ok"}
```

#### 6.2. Truy cập API Documentation
Mở trình duyệt và truy cập:
- **Swagger UI**: http://your-server-ip:8080/docs
- **ReDoc**: http://your-server-ip:8080/redoc

#### 6.3. Test MongoDB Connection
Kiểm tra logs của application để xem đã kết nối MongoDB thành công:
```bash
# Nếu dùng systemd
sudo journalctl -u security-hardening | grep MongoDB

# Hoặc nếu chạy trực tiếp, xem output console
# Sẽ có dòng: ✅ Connected to MongoDB Docker container successfully!
```

---

## Firewall Configuration

### Mở port 8080 cho API
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 8080/tcp
sudo ufw reload

# Firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

---

## API Endpoints

### Audit Endpoints
- `POST /audit/auto-detect` - Tự động phát hiện OS và audit
- `POST /audit/linux` - Audit Linux server qua SSH
- `POST /audit/windows` - Audit Windows server qua WinRM

### Remediation Endpoints
- `POST /remediate/linux` - Chạy remediation script cho Linux
- `POST /remediate/windows` - Chạy remediation script cho Windows

### Rollback Endpoints
- `POST /rollback/linux` - Rollback Linux system
- `POST /rollback/windows` - Rollback Windows system
- `GET /backups/linux` - Danh sách backups Linux
- `GET /backups/windows` - Danh sách backups Windows

### Reporting Endpoints
- `GET /reports/audits` - Lịch sử audit reports
- `GET /reports/remediations` - Lịch sử remediation
- `GET /reports/hosts` - Overview tất cả hosts
- `GET /reports/compliance-stats` - Thống kê compliance

### Utilities
- `GET /rules` - Danh sách security rules
- `POST /rules/sync` - Import rules từ SCAP/XCCDF/YAML vào `content/rules/auto`
- `GET /healthz` - Health check
- `GET /version` - Version info

**Chi tiết API**: Xem tại http://your-server-ip:8080/docs

---

## Troubleshooting

### MongoDB không kết nối được
```bash
# Kiểm tra container MongoDB
docker ps | grep mongodb

# Khởi động lại MongoDB
docker compose restart mongodb

# Kiểm tra logs
docker compose logs mongodb

# Test connection từ host
docker compose exec mongodb mongosh --eval "db.runCommand('ping')"
```

### Python dependencies lỗi
```bash
cd backend
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

### Port 8080 đã được sử dụng
```bash
# Tìm process đang dùng port 8080
sudo lsof -i :8080
# hoặc
sudo netstat -tulpn | grep 8080

# Kill process hoặc đổi port trong uvicorn command
uvicorn main:app --host 0.0.0.0 --port 8081
```

### Permission denied
```bash
# Đảm bảo user có quyền truy cập thư mục project
sudo chown -R $USER:$USER /opt/security_hardening

# Đảm bảo scripts có quyền execute
chmod +x scripts/*.sh
```

### Service không start
```bash
# Kiểm tra logs
sudo journalctl -u security-hardening -n 50

# Kiểm tra syntax service file
sudo systemd-analyze verify /etc/systemd/system/security-hardening.service

# Kiểm tra đường dẫn trong service file
```

---

## Backup & Maintenance

### Backup MongoDB Data
```bash
# Backup MongoDB data
docker compose exec mongodb mongodump --archive=/data/backup/backup-$(date +%Y%m%d).archive --db=security_hardening

# Restore từ backup
docker compose exec mongodb mongorestore --archive=/data/backup/backup-YYYYMMDD.archive
```

### Update Application
```bash
cd /opt/security_hardening
# Pull code mới hoặc copy files mới
cd backend
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart security-hardening
```

---

## Security Notes

⚠️ **Quan trọng**:
- API không có authentication mặc định - Nên thêm authentication (API keys, JWT) trước khi deploy production
- MongoDB đang chạy trên port mặc định - Nên config firewall và authentication
- SSH keys và passwords được truyền qua API - Sử dụng HTTPS trong production
- Backup MongoDB data thường xuyên

---

## Support & Documentation

- **API Docs**: http://your-server-ip:8080/docs
- **Health Check**: http://your-server-ip:8080/healthz
- **Rules Documentation**: Xem trong `content/rules/README.md`

---

## License

[Thêm license của bạn ở đây]
