"""Windows audit module using WinRM."""
import winrm
from typing import Dict, List, Optional
import time

def winrm_connect(host: str, username: str, password: str) -> winrm.Session:
    """Kết nối WinRM với username/password."""
    try:
        session = winrm.Session(
            host,
            auth=(username, password),
            transport='plaintext'
        )
        return session
    except Exception as e:
        raise Exception(f"WinRM connection failed: {e}")

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

def test_winrm_connection(host: str, username: str, password: str) -> Dict:
    """Test kết nối WinRM cơ bản."""
    try:
        session = winrm_connect(host, username, password)
        result = session.run_cmd('hostname')
        
        return {
            "status": "SUCCESS",
            "hostname": result.std_out.decode().strip(),
            "exit_code": result.status_code,
            "message": "WinRM connection successful"
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "error": str(e),
            "message": "WinRM connection failed"
        }
