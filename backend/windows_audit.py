"""Windows audit module."""
import paramiko
from typing import List, Dict, Optional
from linux_audit import ssh_connect  # Windows dùng SSH tạm thời


def run_audit(ssh: paramiko.SSHClient, rule: Dict) -> Dict:
    """Audit Windows rule (legacy SSH-based)."""
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

