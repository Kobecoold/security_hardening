from fastapi import FastAPI, HTTPException, Form
from typing import List, Dict, Optional
import time

# Import từ các module mới
from utils import load_rules, load_rules_by_os, load_remediation_script, load_windows_remediation_script
from linux_audit import detect_os, ssh_connect, run_bash_check_stdin, truncate_output
from windows_audit import winrm_connect, run_winrm_audit, get_windows_host_info, detect_os_windows


app = FastAPI(
    title="Security Hardening Audit Engine",
    swagger_ui_parameters={
        "displayRequestDuration": True,
        "tryItOutEnabled": True,
    },
)

@app.post("/audit/auto-detect")
async def audit_auto_detect(
    host: str = Form(...),
    username: str = Form(""),
    key_path: Optional[str] = Form(None),
    password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    use_sudo: bool = Form(False),
    sudo_password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
):
    """Tự động phát hiện OS và chạy audit phù hợp."""
    try:
        print(f"🔍 Auto-detecting OS for host: {host}")
        
        # Thử SSH trước (Linux)
        try:
            print("🔄 Attempting SSH connection...")
            ssh = ssh_connect(host, username, key_path or "", password=password)
            detected_os = detect_os(ssh)
            ssh.close()
            
            if detected_os:
                print(f"✅ Detected Linux OS: {detected_os}")
                # Chuyển hướng đến audit Linux
                return await audit_linux_json(
                    Host=host,
                    Username=username,
                    Key_path=key_path,
                    Password=password,
                    Use_sudo=use_sudo,
                    Sudo_password=sudo_password
                )
        except Exception as ssh_error:
            print(f"❌ SSH failed: {ssh_error}")
        
        # Thử WinRM (Windows)
        try:
            print("🔄 Attempting WinRM connection...")
            session = winrm_connect(host, "Window", password or "window")
            host_info = get_windows_host_info(session)
            
            if host_info["status"] == "SUCCESS":
                print(f"✅ Detected Windows OS: {host_info['os_type']} - Hostname: {host_info['hostname']}")
                # Chuyển hướng đến audit Windows
                return await audit_windows_winrm(
                    host=host,
                    username="Window",
                    password=password or "window"
                )
            else:
                print(f"❌ WinRM connection failed: {host_info['error']}")
                
        except Exception as winrm_error:
            print(f"❌ WinRM failed: {winrm_error}")
        
        # Nếu cả hai đều thất bại
        raise HTTPException(
            status_code=400,
            detail="Không thể tự động nhận diện OS. Vui lòng kiểm tra: "
                   "1. Kết nối mạng, 2. Thông tin đăng nhập, 3. Dịch vụ SSH/WinRM"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Auto-detection error: {str(e)}")

@app.post("/audit/windows")
async def audit_windows_winrm(
    host: str = Form(...),
    username: str = Form("Window"),
    password: str = Form(..., json_schema_extra={"format": "password"}),
):
    """Audit Windows using WinRM."""
    try:
        # Kết nối WinRM
        session = winrm_connect(host, username, password)
        
        # Lấy thông tin host
        host_info = get_windows_host_info(session)
        if host_info["status"] != "SUCCESS":
            raise HTTPException(status_code=400, detail=f"WinRM connection failed: {host_info['error']}")
        
        # Load rules WinRM
        rules = load_rules()
        
        # Chạy audit
        audit_results = []
        for rule in rules:
            audit_results.append(run_winrm_audit(session, rule))
        
        return {
            "client_type": "windows",
            "protocol": "winrm",
            "host": host,
            "hostname": host_info["hostname"],
            "os_type": host_info["os_type"],
            "benchmark": "CIS Windows 10 Level 1",
            "total_rules": len(audit_results),
            "connection_info": host_info,
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

@app.post("/remediate/windows")
async def remediate_windows(
    host: str = Form(...),
    username: str = Form("Window"),
    password: str = Form(..., json_schema_extra={"format": "password"}),
    script_name: str = Form("fix-security-policies.ps1"),
):
    """Chạy remediation script từ file để fix Windows security issues."""
    try:
        # Load script từ file
        script_content = load_windows_remediation_script(script_name)
        if not script_content:
            raise HTTPException(status_code=404, detail=f"Remediation script not found: {script_name}")
        
        # Kết nối WinRM
        session = winrm_connect(host, username, password)
        
        # Chạy script qua WinRM
        result = session.run_ps(script_content)
        
        output = result.std_out.decode('utf-8', errors='ignore')
        error = result.std_err.decode('utf-8', errors='ignore')
        
        return {
            "status": "SUCCESS" if result.status_code == 0 else "PARTIAL",
            "host": host,
            "script_used": script_name,
            "exit_code": result.status_code,
            "output": output,
            "error": error,
            "message": f"Remediation script '{script_name}' executed successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
