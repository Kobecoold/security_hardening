from fastapi import FastAPI
import paramiko
import os
import json
from typing import Dict

app = FastAPI(title="Security Hardening Audit Engine")

def ssh_connect(host: str, username: str, key_path: str) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=username, key_filename=os.path.expanduser(key_path))
    return ssh

def run_audit(ssh: paramiko.SSHClient, rule: Dict) -> Dict:
    rule_id = rule.get("rule_id")
    description = rule.get("description")
    command = rule.get("command")
    
    stdin, stdout, stderr = ssh.exec_command(command)
    result = stdout.read().decode().strip() or stderr.read().decode().strip()
    status = "PASS" if "expected_output" in rule and rule["expected_output"] in result else "FAIL"
    
    return {
        "rule_id": rule_id,
        "description": description,
        "command": command,
        "result": result,
        "status": status
    }

@app.post("/audit/windows")
async def audit_windows(host: str, username: str = "Window", key_path: str = "~/.ssh/id_ed25519"):
    ssh = ssh_connect(host, username, key_path)
    
    rules = [
        {
            "rule_id": "W1.1.1",
            "description": "Check if SSHD service is running",
            "command": "sc query sshd",
            "expected_output": "STATE              : 4  RUNNING"  # Kiểm tra trạng thái chạy
        },
        {
            "rule_id": "W1.1.2",
            "description": "Check if hosts file exists",
            "command": "dir C:\\Windows\\System32\\drivers\\etc\\hosts",
            "expected_output": "hosts"
        }
    ]
    
    audit_results = [run_audit(ssh, rule) for rule in rules]
    ssh.close()
    
    return {"client_type": "windows", "host": host, "results": audit_results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, reload=True)
