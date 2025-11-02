from fastapi import FastAPI, HTTPException, Form
from pydantic import BaseModel, Field
import paramiko
import yaml
import os
from typing import List, Dict, Optional
import json
import uuid
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed


app = FastAPI(
    title="Security Hardening Audit Engine",
    swagger_ui_parameters={
        "displayRequestDuration": True,
        "tryItOutEnabled": True,
    },
)

# Đường dẫn tới thư mục rule gốc (tương đối theo repo)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
RULES_DIR = os.path.join(REPO_ROOT, "content", "rules")

# Giữ lại đường dẫn Windows hiện tại để tương thích (nếu file tồn tại)
RULES_FILE = os.path.join(RULES_DIR, "windows-11", "cis-windows10-level1.yaml")


def load_rules() -> List[Dict]:
    """Đọc và parse file YAML (Windows legacy)."""
    if not os.path.exists(RULES_FILE):
        raise FileNotFoundError(f"Rule file not found: {RULES_FILE}")

    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_rules_by_os(os_name: str) -> List[Dict]:
    """Nạp tất cả rule YAML theo thư mục hệ điều hành, ví dụ: ubuntu-22.04, debian-12.

    Hỗ trợ cấu trúc phẳng hoặc theo subfolder (kernel, ssh, network...).
    Trả về danh sách rule (mỗi rule là dict). Hỗ trợ cả file YAML trả về 1 rule hoặc danh sách rule.
    """
    os_dir = os.path.join(RULES_DIR, os_name)
    if not os.path.isdir(os_dir):
        raise FileNotFoundError(f"Rules directory not found for OS '{os_name}': {os_dir}")

    rules: List[Dict] = []
    
    # Đệ quy tìm tất cả file .yaml/.yml
    for root, dirs, files in os.walk(os_dir):
        for entry in sorted(files):
            if not entry.lower().endswith((".yml", ".yaml")):
                continue
            file_path = os.path.join(root, entry)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data is None:
                        continue
                    if isinstance(data, list):
                        rules.extend(data)
                    elif isinstance(data, dict):
                        rules.append(data)
            except Exception as exc:
                # Bỏ qua file hỏng nhưng ghi chú lỗi trong kết quả gọi API cấp trên
                raise HTTPException(status_code=500, detail=f"Failed to load rules from {file_path}: {exc}")
    return rules


def detect_os(ssh: paramiko.SSHClient) -> Optional[str]:
    """Auto-detect OS bằng cách đọc /etc/os-release."""
    stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release")
    output = stdout.read().decode().strip()
    stderr.read()  # discard errors
    
    # Parse ID và VERSION_ID
    os_id = None
    version = None
    for line in output.splitlines():
        if line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"\'')
        elif line.startswith("VERSION_ID="):
            version = line.split("=", 1)[1].strip().strip('"\'')
    
    if not os_id or not version:
        return None
    
    # Map ID/version thành tên rule folder
    if os_id in ["ubuntu", "debian"]:
        return f"{os_id}-{version}"
    # Có thể thêm các distro khác ở đây
    return None


def filter_rules(
    rules: List[Dict],
    ids: Optional[List[str]] = None,
    level: Optional[str] = None,
    benchmark: Optional[str] = None,
) -> List[Dict]:
    filtered: List[Dict] = []
    ids_set = set(ids or [])
    for r in rules:
        if ids_set and r.get("id") not in ids_set:
            continue
        if level and str(r.get("level")) != str(level):
            continue
        if benchmark and r.get("benchmark") != benchmark:
            continue
        filtered.append(r)
    return filtered

def ssh_connect(host: str, username: str, key_path: str, password: Optional[str] = None) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Chuẩn hóa đường dẫn key và loại bỏ dấu quote vô tình nhập
    key_filename = os.path.expanduser(key_path).strip().strip("\"'") if key_path else None

    connect_kwargs = {
        "hostname": host,
        "username": username,
        "timeout": 10,
    }

    if key_filename and os.path.exists(key_filename):
        connect_kwargs["key_filename"] = key_filename
    elif password:
        # Fallback dùng mật khẩu nếu không có private key
        connect_kwargs["password"] = password
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    else:
        # Key không tồn tại và không có password
        raise FileNotFoundError(
            f"SSH key not found: '{key_filename}'. Provide a valid key_path or a password."
        )

    ssh.connect(**connect_kwargs)
    return ssh

def run_bash_check(
    ssh: paramiko.SSHClient,
    script_text: str,
    use_sudo: bool = False,
    sudo_password: Optional[str] = None,
) -> Dict:
    """Upload và chạy script bash trên máy từ xa. PASS nếu exit code = 0.

    Nếu cần sudo và có sudo_password, truyền password qua stdin bằng sudo -S.
    """
    sftp = ssh.open_sftp()
    tmp_path = f"/tmp/audit_{uuid.uuid4().hex}.sh"
    try:
        with sftp.file(tmp_path, "w") as remote_file:
            remote_file.write(script_text)
        sftp.chmod(tmp_path, 0o700)

        base_command = f"bash {tmp_path}"
        if use_sudo and sudo_password:
            command = f"sudo -S -p '' {base_command}"
            stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)
            try:
                stdin.write(f"{sudo_password}\n")
                stdin.flush()
            except Exception:
                pass
        elif use_sudo:
            command = f"sudo -n {base_command}"
            stdin, stdout, stderr = ssh.exec_command(command)
        else:
            command = base_command
            stdin, stdout, stderr = ssh.exec_command(command)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()

        return {
            "stdout": out,
            "stderr": err,
            "exit_status": exit_status,
            "status": "PASS" if exit_status == 0 else "FAIL",
        }
    finally:
        try:
            sftp.remove(tmp_path)
        except Exception:
            pass
        sftp.close()

def run_bash_check_stdin(
    ssh: paramiko.SSHClient,
    script_text: str,
    use_sudo: bool = False,
    sudo_password: Optional[str] = None,
) -> Dict:
    base = "bash -s"
    if use_sudo and sudo_password:
        command = f"sudo -S -p '' {base}"
        stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)
        try:
            stdin.write(f"{sudo_password}\n")
            stdin.flush()
        except Exception:
            pass
    elif use_sudo:
        command = f"sudo -n {base}"
        stdin, stdout, stderr = ssh.exec_command(command)
    else:
        command = base
        stdin, stdout, stderr = ssh.exec_command(command)

    try:
        stdin.write(script_text)
        stdin.flush()
    finally:
        try:
            stdin.channel.shutdown_write()
        except Exception:
            pass

    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    exit_status = stdout.channel.recv_exit_status()
    return {
        "stdout": out,
        "stderr": err,
        "exit_status": exit_status,
        "status": "PASS" if exit_status == 0 else "FAIL",
    }

def truncate_output(text: str, limit: int = 8192) -> Dict:
    if text is None:
        return {"text": "", "truncated": False}
    if len(text) <= limit:
        return {"text": text, "truncated": False}
    return {
        "text": text[:limit],
        "truncated": True,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }

def run_audit(ssh: paramiko.SSHClient, rule: Dict) -> Dict:
    command = rule["check"]["cmd"]
    expected = rule["check"]["expected"]

    stdin, stdout, stderr = ssh.exec_command(command)
    result = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    if error:
        output = error
    else:
        output = result

    status = "PASS" if expected in output else "FAIL"

    return {
        "id": rule["id"],
        "title": rule["title"],
        "command": command,
        "result": output,
        "expected": expected,
        "status": status
    }

@app.post("/audit/windows")
async def audit_windows(
    host: str,
    username: str = "Window",
    key_path: str = "~/.ssh/id_ed25519",
    password: Optional[str] = None,
):
    try:
        ssh = ssh_connect(host, username, key_path, password=password)
        rules = load_rules()
        
        audit_results = []
        for rule in rules:
            if rule.get("os") == "windows-10":
                audit_results.append(run_audit(ssh, rule))
        
        ssh.close()
        
        return {
            "client_type": "windows",
            "host": host,
            "benchmark": "CIS Windows 10 Level 1",
            "total_rules": len(audit_results),
            "results": audit_results
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# Optional: API để lấy danh sách rule
@app.get("/rules")
async def get_rules(os_name: Optional[str] = None):
    try:
        if os_name:
            return {"rules": load_rules_by_os(os_name)}
        return {"rules": load_rules()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class LinuxAuditRequest(BaseModel):
    host: str
    os_name: str
    username: str = Field(default="")
    key_path: Optional[str] = Field(default="~/.ssh/id_ed25519")
    password: Optional[str] = None
    use_sudo: bool = False
    sudo_password: Optional[str] = None
    ids: Optional[List[str]] = None
    level: Optional[str] = None
    benchmark: Optional[str] = None
    max_parallel: int = 1
    timeout_seconds: int = 60


@app.post("/audit/linux")
async def audit_linux_json(
    Host: str = Form(...),
    Username: str = Form(""),
    Key_path: Optional[str] = Form("~/.ssh/id_ed25519"),
    Password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    Use_sudo: bool = Form(False),
    Sudo_password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
):
    try:
        # Kết nối SSH trước để auto-detect OS
        ssh = ssh_connect(Host, Username, Key_path or "", password=Password)
        try:
            detected_os = detect_os(ssh)
            if not detected_os:
                raise HTTPException(
                    status_code=400,
                    detail="Không thể phát hiện OS tự động. Hệ thống có thể không phải Linux hoặc không được hỗ trợ."
                )
        finally:
            ssh.close()
        
        all_rules = load_rules_by_os(detected_os)
        # Không filter, chạy tất cả rules của OS đó
        rules = all_rules
        if not rules:
            return {
                "client_type": "linux",
                "host": Host,
                "os": detected_os,
                "total_rules": 0,
                "results": [],
            }

        results: List[Dict] = []
        start_overall = time.time()

        def run_one(rule: Dict) -> Dict:
            check = rule.get("check", {}) if isinstance(rule, dict) else {}
            script_text = check.get("bash") if isinstance(check, dict) else None
            if not script_text:
                return {"id": rule.get("id"), "title": rule.get("title"), "status": "SKIPPED", "reason": "no check.bash"}
            effective_use_sudo = bool(rule.get("needs_sudo", False) or Use_sudo)
            started = time.time()
            ssh_local = ssh_connect(Host, Username, Key_path or "", password=Password)
            try:
                exec_result = run_bash_check_stdin(
                    ssh_local,
                    script_text,
                    use_sudo=effective_use_sudo,
                    sudo_password=Sudo_password,
                )
            finally:
                try:
                    ssh_local.close()
                except Exception:
                    pass
            duration_ms = int((time.time() - started) * 1000)
            tout = truncate_output(exec_result["stdout"]) 
            terr = truncate_output(exec_result["stderr"]) 
            return {
                "id": rule.get("id"),
                "title": rule.get("title"),
                "os": rule.get("os"),
                "benchmark": rule.get("benchmark"),
                "needs_sudo": effective_use_sudo,
                "exit_status": exec_result["exit_status"],
                "status": exec_result["status"],
                "stdout": tout,
                "stderr": terr,
                "duration_ms": duration_ms,
                "started_at": int(started * 1000),
            }

        # Chạy tuần tự (không cần parallel cho audit)
        for rule in rules:
            results.append(run_one(rule))

        return {
            "client_type": "linux",
            "host": Host,
            "os": detected_os,
            "total_rules": len(results),
            "duration_ms": int((time.time() - start_overall) * 1000),
            "results": results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/version")
async def version():
    return {"name": "security_hardening", "api": "v1"}
