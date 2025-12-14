"""Windows audit module using WinRM."""
import winrm
from typing import Dict, Optional
import time
import re  # THÊM IMPORT

def winrm_connect(host: str, username: str, password: str) -> winrm.Session:
    """Kết nối WinRM với username/password qua HTTPS hoặc HTTP."""
    # Thử HTTPS trước (port 5986)
    try:
        session = winrm.Session(
            host,
            auth=(username, password),
            transport='ssl',
            server_cert_validation='ignore'
        )
        # Test connection
        test_result = session.run_cmd('echo test')
        if test_result.status_code is not None:
            return session
    except Exception as ssl_error:
        print(f"⚠️ WinRM HTTPS (port 5986) failed, trying HTTP: {ssl_error}")
        # Fallback sang HTTP nếu HTTPS không hoạt động
        try:
            session = winrm.Session(
                host,
                auth=(username, password),
                transport='ntlm',
                server_cert_validation='ignore'
            )
            # Test connection
            test_result = session.run_cmd('echo test')
            if test_result.status_code is not None:
                return session
        except Exception as http_error:
            error_msg = (
                f"WinRM connection failed to {host}.\n"
                f"HTTPS (port 5986) error: Connection refused\n"
                f"HTTP (port 5985) error: Connection refused\n\n"
                f"Possible causes:\n"
                f"1. WinRM service is not running\n"
                f"2. WinRM is not enabled/configured\n"
                f"3. Firewall is blocking ports 5985/5986\n"
                f"4. Network connectivity issue\n\n"
                f"To fix (run PowerShell as Administrator):\n"
                f"  Enable-PSRemoting -Force\n"
                f"  winrm quickconfig\n"
                f"  Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management'"
            )
            raise Exception(error_msg)
    
    raise Exception("WinRM connection test failed")

def detect_os_windows(session: winrm.Session) -> Optional[str]:
    """Auto-detect Windows OS version một cách chính xác."""
    try:
        # Lấy thông tin OS từ systeminfo
        result = session.run_cmd('systeminfo | findstr /B /C:"OS Name"')
        
        if result.status_code != 0:
            return None
            
        output = result.std_out.decode('utf-8', errors='ignore')
        output = output.replace('\r\n', '\n').replace('\r', '\n').strip()
        
        # Lấy version number từ wmic
        result_ver = session.run_cmd('wmic os get version')
        version_output = ""
        if result_ver.status_code == 0:
            version_output = result_ver.std_out.decode('utf-8', errors='ignore')
        
        # Parse OS name và version
        # Windows 10/11 detection dựa trên build number
        if "Windows 10" in output or "Windows 11" in output:
            # Tìm build number từ version output
            match = re.search(r'10\.0\.(\d+)', version_output)
            if match:
                build_number = int(match.group(1))
                # Windows 11 build number bắt đầu từ 22000
                if build_number >= 22000:
                    return "windows-11"
            # Mặc định là windows-10 nếu không tìm thấy hoặc build < 22000
            return "windows-10"
        elif "Windows Server" in output:
            if "2016" in output:
                return "windows-server-2016"
            elif "2019" in output:
                return "windows-server-2019" 
            elif "2022" in output:
                return "windows-server-2022"
            else:
                return "windows-server"
        else:
            return "windows-unknown"
            
    except Exception as e:
        print(f"Windows OS detection failed: {e}")
        return None

def get_windows_host_info(session: winrm.Session) -> Dict:
    """Lấy thông tin host Windows."""
    try:
        # Lấy hostname
        result = session.run_cmd('hostname')
        hostname = result.std_out.decode().strip() if result.status_code == 0 else "Unknown"
        
        # Detect OS với hàm đã cập nhật
        os_type = detect_os_windows(session)
        
        # Lấy thêm thông tin (optional)
        result_ip = session.run_cmd('ipconfig | findstr IPv4')
        ip_address = result_ip.std_out.decode().split(':')[-1].strip() if result_ip.status_code == 0 else "Unknown"
        
        return {
            "status": "SUCCESS",
            "hostname": hostname,
            "os_type": os_type,
            "ip_address": ip_address,
            "exit_code": result.status_code,
            "message": "WinRM connection successful"
        }
    except Exception as e:
        return {
            "status": "FAILED", 
            "error": str(e),
            "message": "WinRM connection failed"
        }

def run_winrm_audit(session: winrm.Session, rule: Dict) -> Dict:
    """Audit Windows rule using WinRM."""
    if "check" not in rule:
        return {
            "id": rule.get("id", "unknown"),
            "title": rule.get("title", "Unknown"),
            "status": "SKIPPED",
            "error": "Rule missing 'check' field",
            "command": "N/A",
            "result": "",
            "expected": "N/A",
            "exit_code": -1,
            "duration_ms": 0
        }
    
    check = rule["check"]
    if "winrm" not in check:
        return {
            "id": rule.get("id", "unknown"),
            "title": rule.get("title", "Unknown"),
            "status": "SKIPPED",
            "error": "Rule missing 'check.winrm' field",
            "command": "N/A",
            "result": "",
            "expected": check.get("expected", "N/A"),
            "exit_code": -1,
            "duration_ms": 0
        }
    
    command = check["winrm"]
    expected = check.get("expected", "")
    
    try:
        start_time = time.time()
        
        # Chạy command qua WinRM
        result = session.run_cmd(command)
        duration_ms = int((time.time() - start_time) * 1000)
        
        if result.status_code == 0:
            output = result.std_out.decode('utf-8', errors='ignore')
            error_output = result.std_err.decode('utf-8', errors='ignore')
        else:
            output = result.std_err.decode('utf-8', errors='ignore')
            error_output = ""
        
        # Normalize line endings
        output = output.replace('\r\n', '\n').replace('\r', '\n')
        error_output = error_output.replace('\r\n', '\n').replace('\r', '\n')
        
        # Kiểm tra kết quả
        status = "PASS" if expected in output else "FAIL"
        
        return {
            "id": rule["id"],
            "title": rule["title"],
            "command": command,
            "result": output,
            "error": error_output,
            "expected": expected,
            "status": status,
            "exit_code": result.status_code,
            "duration_ms": duration_ms
        }
        
    except Exception as e:
        return {
            "id": rule["id"],
            "title": rule["title"],
            "command": command,
            "result": str(e),
            "error": "",
            "expected": expected,
            "status": "ERROR",
            "exit_code": -1,
            "duration_ms": 0
        }
