"""Windows audit module using WinRM."""
import winrm
from typing import Dict, Optional
import time

def winrm_connect(host: str, username: str, password: str) -> winrm.Session:
    """Kết nối WinRM với username/password qua HTTPS."""
    try:
        session = winrm.Session(
            host,
            auth=(username, password),
            transport='ssl',
            server_cert_validation='ignore'
        )
        return session
    except Exception as e:
        raise Exception(f"WinRM HTTPS connection failed: {e}")

def detect_os_windows(session: winrm.Session) -> Optional[str]:
    """Auto-detect Windows OS version using systeminfo."""
    try:
        # Chạy systeminfo để lấy thông tin OS
        result = session.run_cmd('systeminfo | findstr /B /C:"OS Name"')
        
        if result.status_code != 0:
            return None
            
        output = result.std_out.decode('utf-8', errors='ignore').strip()
        
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
    command = rule["check"]["winrm"]
    expected = rule["check"]["expected"]
    
    try:
        start_time = time.time()
        
        # Chạy command qua WinRM
        result = session.run_cmd(command)
        duration_ms = int((time.time() - start_time) * 1000)
        
        if result.status_code == 0:
            output = result.std_out.decode('utf-8', errors='ignore').strip()
            error_output = result.std_err.decode('utf-8', errors='ignore').strip()
        else:
            output = result.std_err.decode('utf-8', errors='ignore').strip()
            error_output = ""
        
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