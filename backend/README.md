# Security Hardening Backend (Python, Agentless)

## Thành phần
- **FastAPI**: Xây dựng REST API platform để gọi kiểm tra client Linux (qua SSH), Windows (WinRM/PowerShell)
- **Rule**: Lưu mẫu YAML (content/rules) – chứa script kiểm tra và script remediation Bash/Python/PowerShell
- **Quản trị**: Chỉ cần cài đặt trên 1 server

## Chạy dev nhanh
1. Install Python 3.9 trở lên.
2. Tạo virtualenv:
   ```
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Khởi động API server:
   ```
   uvicorn main:app --reload --host 0.0.0.0 --port 8080
   ```
4. Đọc docs tự động (Swagger): http://localhost:8080/docs

## Cấu trúc
```
backend/
  main.py           # Entrypoint FastAPI server
  requirements.txt  # Thư viện
  README.md         # Hướng dẫn
content/rules/      # Nơi lưu các rule YAML/check script
```

## Tiếp theo
- Thêm API nhận cấu hình asset, kiểm tra, chạy script Bash/PowerShell từ xa agentless.
- Triển khai job queue và lưu log kết quả kiểm tra.


## Set Up a Virtual Environment
   ```
   python3 -m venv .venv
   source .venv/bin/activate
   ```
## Install Dependencies
   ```
   pip install -r requirements.txt
   ```
## Run the Application
   ```
   uvicorn main:app --reload --host 0.0.0.0 --port 8080
   ```
## Test the Audit Engine
   ```
   curl -X POST "http://localhost:8080/audit/windows?host=192.168.206.151&username=Window&key_path=~/.ssh/id_ed25519"
   ```
## Kết quả
   ```
   {
  "client_type": "windows",
  "host": "192.168.206.151",
  "benchmark": "CIS Windows 10 Level 1",
  "total_rules": 2,
  "results": [
    {
      "id": "cis-windows10-18.9.1",
      "title": "Ensure 'OpenSSH Server' service is running",
      "command": "sc query sshd",
      "result": "...STATE : 4 RUNNING...",
      "expected": "STATE              : 4  RUNNING",
      "status": "PASS"
    },
    {
      "id": "cis-windows10-2.3.11.1",
      "title": "Ensure 'hosts' file exists and is not empty",
      "command": "dir C:\\Windows\\System32\\drivers\\etc\\hosts",
      "result": "...824 hosts...",
      "expected": "hosts",
      "status": "PASS"
    }
  ]
}
   ```