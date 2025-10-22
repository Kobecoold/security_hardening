# Security Hardening Agentless (Python)

## Overview
- Backend Python (FastAPI): API kiểm tra máy chủ Linux/Windows từ xa qua SSH/WinRM
- Lưu rule/scripts dạng YAML + Bash/Python/PowerShell (content/rules)
- Dashboard sẽ thêm sau (chỉ làm API trước)

### Tree
```
backend/            # Python API
content/rules/      # Rule YAML/script
scripts/            # Script tiện ích
```

## Run Backend
```bash
cd backend
python3 -m venv .venv
.venv\Scripts\activate  # Nếu dùng Windows
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8080
```
API docs: http://localhost:8080/docs
