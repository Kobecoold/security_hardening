"""Linux audit module."""
import paramiko
import os
import time
import hashlib
from typing import List, Dict, Optional


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
    return None


def ssh_connect(host: str, username: str, key_path: str, password: Optional[str] = None) -> paramiko.SSHClient:
    """Kết nối SSH với key hoặc password."""
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


def run_bash_check_stdin(
    ssh: paramiko.SSHClient,
    script_text: str,
    use_sudo: bool = False,
    sudo_password: Optional[str] = None,
) -> Dict:
    """Truyền script qua stdin. PASS nếu exit code = 0."""
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
    """Truncate output nếu quá dài và trả về hash để reference."""
    if text is None:
        return {"text": "", "truncated": False}
    if len(text) <= limit:
        return {"text": text, "truncated": False}
    return {
        "text": text[:limit],
        "truncated": True,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }

