"""Windows audit module using WinRM."""
import winrm
from typing import Dict, Optional
import time

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
        # Test connection bằng cách chạy một command đơn giản
        test_result = session.run_cmd('echo test')
        if test_result.status_code is not None:
            return session
    except Exception as ssl_error:
        print(f"⚠️ WinRM HTTPS (port 5986) failed, trying HTTP: {ssl_error}")
        # Fallback sang HTTP nếu HTTPS không hoạt động (port 5985)
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
            # Tạo error message rõ ràng hơn
            error_msg = (
                f"WinRM connection failed to {host}.\n"
                f"HTTPS (port 5986) error: Connection refused\n"
                f"HTTP (port 5985) error: Connection refused\n\n"
                f"Possible causes:\n"
                f"1. WinRM service is not running on Windows server\n"
                f"2. WinRM is not enabled/configured\n"
                f"3. Firewall is blocking ports 5985 (HTTP) or 5986 (HTTPS)\n"
                f"4. Network connectivity issue\n\n"
                f"To fix on Windows server (run PowerShell as Administrator):\n"
                f"  Enable-PSRemoting -Force\n"
                f"  winrm quickconfig\n"
                f"  Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management'"
            )
            raise Exception(error_msg)
    
    raise Exception("WinRM connection test failed - unable to execute test command")

def detect_os_windows(session: winrm.Session) -> Optional[str]:
    """Auto-detect Windows OS version using systeminfo."""
    try:
        # Chạy systeminfo để lấy thông tin OS
        result = session.run_cmd('systeminfo | findstr /B /C:"OS Name"')
        
        if result.status_code != 0:
            return None
            
        output = result.std_out.decode('utf-8', errors='ignore')
        # Normalize line endings
        output = output.replace('\r\n', '\n').replace('\r', '\n').strip()
        
        # Parse OS name và version
        if "Windows 10" in output:
            return "windows-10"
        elif "Windows 11" in output:
            return "windows-11"
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
    """Lấy thông tin host Windows thay thế cho test_winrm_connection."""
    try:
        # Lấy hostname
        result = session.run_cmd('hostname')
        hostname = result.std_out.decode().strip() if result.status_code == 0 else "Unknown"
        
        # Detect OS
        os_type = detect_os_windows(session)
        
        return {
            "status": "SUCCESS",
            "hostname": hostname,
            "os_type": os_type,
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
    # Kiểm tra cấu trúc rule
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
        
        # Normalize line endings: \r\n -> \n, và clean up
        output = output.replace('\r\n', '\n').replace('\r', '\n')
        error_output = error_output.replace('\r\n', '\n').replace('\r', '\n')
        
        # Strip leading/trailing whitespace nhưng giữ lại line breaks bên trong
        output = output.strip()
        error_output = error_output.strip()
        
        # Kiểm tra kết quả (so sánh với output đã normalize)
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