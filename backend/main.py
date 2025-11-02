from fastapi import FastAPI, HTTPException, Form
from typing import List, Dict, Optional
import time

# Import từ các module mới
from utils import load_rules, load_rules_by_os, load_remediation_script
from linux_audit import detect_os, ssh_connect, run_bash_check_stdin, truncate_output
from windows_audit import run_audit


app = FastAPI(
    title="Security Hardening Audit Engine",
    swagger_ui_parameters={
        "displayRequestDuration": True,
        "tryItOutEnabled": True,
    },
)


@app.post("/audit/windows")
async def audit_windows(
    host: str,
    username: str = "Window",
    key_path: str = "~/.ssh/id_ed25519",
    password: Optional[str] = None,
):
    """Audit Windows (legacy SSH-based)."""
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


@app.get("/rules")
async def get_rules(os_name: Optional[str] = None):
    """Lấy danh sách rules."""
    try:
        if os_name:
            return {"rules": load_rules_by_os(os_name)}
        return {"rules": load_rules()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/audit/linux")
async def audit_linux_json(
    Host: str = Form(...),
    Username: str = Form(""),
    Key_path: Optional[str] = Form("~/.ssh/id_ed25519"),
    Password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    Use_sudo: bool = Form(False),
    Sudo_password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
):
    """Audit Linux: auto-detect OS và chạy tất cả CIS rules."""
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

        # Chạy tuần tự
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
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/remediate/linux")
async def remediate_linux(
    Host: str = Form(...),
    Username: str = Form(""),
    Key_path: Optional[str] = Form("~/.ssh/id_ed25519"),
    Password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    Use_sudo: bool = Form(True, description="Phải dùng sudo cho remediation"),
    Sudo_password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    Rule_id: str = Form(..., description="ID của rule cần fix, ví dụ: cis-ubuntu-20.04-5.2.4"),
):
    """Chạy remediation script để fix rule FAIL."""
    try:
        # Kết nối SSH để auto-detect OS
        ssh = ssh_connect(Host, Username, Key_path or "", password=Password)
        detected_os = None
        try:
            detected_os = detect_os(ssh)
            if not detected_os:
                raise HTTPException(status_code=400, detail="Không thể phát hiện OS tự động.")
        finally:
            ssh.close()
        
        # Load remediation script
        script_content = load_remediation_script(detected_os, Rule_id)
        if not script_content:
            raise HTTPException(status_code=404, detail=f"Không tìm thấy remediation script cho rule: {Rule_id}")
        
        # Chạy script
        ssh_exec = ssh_connect(Host, Username, Key_path or "", password=Password)
        try:
            exec_result = run_bash_check_stdin(
                ssh_exec,
                script_content,
                use_sudo=Use_sudo,
                sudo_password=Sudo_password,
            )
        finally:
            ssh_exec.close()
        
        return {
            "rule_id": Rule_id,
            "host": Host,
            "os": detected_os,
            "status": "FIXED" if exec_result["exit_status"] == 0 else "FAILED",
            "stdout": exec_result["stdout"],
            "stderr": exec_result["stderr"],
            "exit_status": exec_result["exit_status"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/version")
async def version():
    """Version endpoint."""
    return {"name": "security_hardening", "api": "v1"}
