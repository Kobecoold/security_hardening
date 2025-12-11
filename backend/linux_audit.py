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
    timeout: int = 300,
) -> Dict:
    """
    Truyền script qua stdin. PASS nếu exit code = 0.
    
    Args:
        timeout: Timeout in seconds (default 300 = 5 minutes)
    """
    import select
    import socket
    
    base = "bash -s"
    if use_sudo and sudo_password:
        command = f"sudo -S -p '' {base}"
        stdin, stdout, stderr = ssh.exec_command(command, get_pty=True, timeout=timeout)
        try:
            stdin.write(f"{sudo_password}\n")
            stdin.flush()
        except Exception:
            pass
    elif use_sudo:
        command = f"sudo -n {base}"
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    else:
        command = base
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    
    try:
        stdin.write(script_text)
        stdin.flush()
    finally:
        try:
            stdin.channel.shutdown_write()
        except Exception:
            pass
    
    # Read output with timeout - Cải thiện để tránh treo
    out = ""
    err = ""
    exit_status = -1
    
    try:
        # Wait for command to complete with timeout - đọc output trong khi chờ
        import time
        import select
        
        start_time = time.time()
        stdout.channel.settimeout(1.0)  # Set socket timeout để có thể đọc non-blocking
        stderr.channel.settimeout(1.0)
        
        # Đọc output trong khi chờ command hoàn thành
        while not stdout.channel.exit_status_ready():
            elapsed = time.time() - start_time
            if elapsed > timeout:
                # Force close channels
                try:
                    stdout.channel.close()
                    stderr.channel.close()
                except:
                    pass
                return {
                    "stdout": out,
                    "stderr": err + f"\n⚠️ Command timeout after {timeout} seconds",
                    "exit_status": 124,  # Standard timeout exit code
                    "status": "TIMEOUT",
                }
            
            # Đọc output nếu có (non-blocking)
            try:
                if stdout.channel.recv_ready():
                    chunk = stdout.channel.recv(4096).decode('utf-8', errors='ignore')
                    out += chunk
                if stderr.channel.recv_stderr_ready():
                    chunk = stderr.channel.recv_stderr(4096).decode('utf-8', errors='ignore')
                    err += chunk
            except socket.timeout:
                # Socket timeout là bình thường khi chờ
                pass
            except Exception:
                # Ignore other errors khi đọc
                pass
            
            # Sleep ngắn để không tốn CPU
            time.sleep(0.1)
        
        # Command đã hoàn thành, đọc phần còn lại
        try:
            remaining_out = stdout.read().decode('utf-8', errors='ignore')
            if remaining_out:
                out += remaining_out
        except:
            pass
        
        try:
            remaining_err = stderr.read().decode('utf-8', errors='ignore')
            if remaining_err:
                err += remaining_err
        except:
            pass
        
        # Lấy exit status
        exit_status = stdout.channel.recv_exit_status()
        
    except socket.timeout:
        return {
            "stdout": out,
            "stderr": err + f"\n⚠️ SSH connection timeout after {timeout} seconds",
            "exit_status": 124,
            "status": "TIMEOUT",
        }
    except Exception as e:
        return {
            "stdout": out,
            "stderr": err + f"\n⚠️ Error reading output: {str(e)}",
            "exit_status": -1,
            "status": "ERROR",
        }
    
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


def get_linux_host_info(ssh: paramiko.SSHClient) -> Dict:
    """Lấy thông tin host Linux tương tự get_windows_host_info."""
    try:
        # Lấy hostname
        stdin, stdout, stderr = ssh.exec_command("hostname")
        hostname = stdout.read().decode().strip()
        exit_code = stdout.channel.recv_exit_status()
        
        if exit_code != 0:
            hostname = "Unknown"
        
        # Detect OS
        os_type = detect_os(ssh)
        
        # Lấy thêm thông tin kernel version (optional)
        stdin, stdout, stderr = ssh.exec_command("uname -r")
        kernel_version = stdout.read().decode().strip() if stdout.channel.recv_exit_status() == 0 else "Unknown"
        
        return {
            "status": "SUCCESS",
            "hostname": hostname,
            "os_type": os_type,
            "kernel_version": kernel_version,
            "exit_code": exit_code,
            "message": "SSH connection successful"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "error": str(e),
            "message": "SSH connection failed"
        }
