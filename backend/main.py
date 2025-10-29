from fastapi import FastAPI, HTTPException
import paramiko
import yaml
import os
from typing import List, Dict
import json

app = FastAPI(title="Security Hardening Audit Engine")

# Đường dẫn tới file YAML
RULES_FILE = "/home/server/security_hardening/content/rules/windows-11/cis-windows10-level1.yaml"

def load_rules() -> List[Dict]:
    """Đọc và parse file YAML chứa các rule"""
    if not os.path.exists(RULES_FILE):
        raise FileNotFoundError(f"Rule file not found: {RULES_FILE}")
    
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def ssh_connect(host: str, username: str, key_path: str) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host,
        username=username,
        key_filename=os.path.expanduser(key_path),
        timeout=10
    )
    return ssh

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
    key_path: str = "~/.ssh/id_ed25519"
):
    try:
        ssh = ssh_connect(host, username, key_path)
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
async def get_rules():
    try:
        return {"rules": load_rules()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
