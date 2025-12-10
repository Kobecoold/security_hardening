from fastapi import FastAPI, HTTPException, Form
from typing import List, Dict, Optional
from database import db
from rollback import rollback_manager
from linux_rollback import linux_rollback_manager

import time
import traceback
from datetime import datetime

# Import từ các module mới
from utils import load_rules, load_rules_by_os, load_remediation_script, load_windows_remediation_script
from linux_audit import detect_os, ssh_connect, run_bash_check_stdin, truncate_output, get_linux_host_info
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
    """Audit Windows using WinRM - Lưu kết quả vào MongoDB."""
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
        
        # Chuẩn bị dữ liệu audit để lưu vào MongoDB
        audit_data = {
            "host": host,
            "os_type": host_info["os_type"],
            "client_type": "windows",
            "protocol": "winrm", 
            "benchmark": "CIS Windows 10 Level 1",
            "total_rules": len(audit_results),
            "results": audit_results,
            "connection_info": host_info
        }
        
        # LƯU VÀO MONGODB - collection: audit_reports
        audit_id = db.save_audit_report(audit_data)
        
        return {
            "audit_id": audit_id,  # ID từ MongoDB
            "client_type": "windows",
            "protocol": "winrm",
            "host": host,
            "hostname": host_info["hostname"],
            "os_type": host_info["os_type"],
            "benchmark": "CIS Windows 10 Level 1",
            "total_rules": len(audit_results),
            "compliance_score": audit_data["compliance_score"],  # Được tính tự động
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

        # Lấy thông tin host
        ssh_info = ssh_connect(Host, Username, Key_path or "", password=Password)
        try:
            host_info = get_linux_host_info(ssh_info)
        finally:
            ssh_info.close()

        # Chuẩn bị dữ liệu audit để lưu vào MongoDB
        audit_data = {
            "host": Host,
            "os_type": detected_os,
            "client_type": "linux",
            "protocol": "ssh",
            "benchmark": rules[0].get("benchmark", "CIS Linux Benchmark") if rules else "Unknown",
            "total_rules": len(results),
            "results": results,
            "connection_info": host_info,
            "duration_ms": int((time.time() - start_overall) * 1000)
        }

        # LƯU VÀO MONGODB - collection: audit_reports
        audit_id = db.save_audit_report(audit_data)

        return {
            "audit_id": audit_id,  # ID từ MongoDB
            "client_type": "linux",
            "protocol": "ssh",
            "host": Host,
            "hostname": host_info.get("hostname", "Unknown"),
            "os": detected_os,
            "benchmark": audit_data["benchmark"],
            "total_rules": len(results),
            "compliance_score": audit_data["compliance_score"],  # Được tính tự động
            "duration_ms": audit_data["duration_ms"],
            "connection_info": host_info,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/healthz")
async def healthz():
    """Health check endpoint."""
    return {"status": "ok"}

# SỬA ENDPOINT REMEDIATION ĐỂ TỰ ĐỘNG TẠO BACKUP
@app.post("/remediate/windows")
async def remediate_windows(
    host: str = Form(...),
    username: str = Form("Window"),
    password: str = Form(..., json_schema_extra={"format": "password"}),
    script_name: str = Form("fix-security-policies.ps1"),
    create_backup: bool = Form(True),
):
    """Chạy remediation script - Tự động tạo backup - Lưu log vào MongoDB."""
    try:
        print(f"🔄 Starting remediation for {host} with username: {username}")
        
        # Kết nối WinRM (dùng hàm cũ đã hoạt động)
        session = winrm_connect(host, username, password)
        print("✅ WinRM connection established")
        
        backup_id = None
        
        # Tạo backup nếu được yêu cầu - KHÔNG BLOCK NẾU LỖI
        if create_backup:
            try:
                print("🔍 Creating backup...")
                backup_id = rollback_manager.create_backup(host, session)
                if backup_id:
                    print(f"✅ Backup created: {backup_id}")
                else:
                    print(f"⚠️ Backup creation returned None (non-critical error)")
            except Exception as backup_error:
                print(f"⚠️ Backup creation failed (non-critical): {backup_error}")
                # KHÔNG RAISE ERROR - tiếp tục remediation
        
        # Load script từ file
        print(f"📄 Loading script: {script_name}")
        script_content = load_windows_remediation_script(script_name)
        if not script_content:
            raise HTTPException(status_code=404, detail=f"Remediation script not found: {script_name}")
        
        # Chạy script remediation
        print("🚀 Running remediation script...")
        result = session.run_ps(script_content)
        
        output = result.std_out.decode('utf-8', errors='ignore')
        error = result.std_err.decode('utf-8', errors='ignore')
        
        print(f"📊 Script result - Exit code: {result.status_code}")
        
        # Chuẩn bị dữ liệu remediation để lưu vào MongoDB
        remediation_data = {
            "host": host,
            "username": username,
            "script_used": script_name,
            "backup_id": backup_id,
            "status": "SUCCESS" if result.status_code == 0 else "PARTIAL",
            "exit_code": result.status_code,
            "output": output,
            "error": error,
            "rollback_status": "AVAILABLE" if backup_id else "NO_BACKUP",
            "created_at": datetime.utcnow()
        }
        
        # LƯU VÀO MONGODB
        remediation_id = db.save_remediation_log(remediation_data)
        
        return {
            "remediation_id": remediation_id,
            "backup_id": backup_id,
            "status": "SUCCESS" if result.status_code == 0 else "PARTIAL",
            "host": host,
            "script_used": script_name,
            "exit_code": result.status_code,
            "output": output[:1000],
            "error": error[:1000],
            "message": f"Remediation script '{script_name}' executed successfully",
            "rollback_available": backup_id is not None
        }
        
    except Exception as e:
        print(f"❌ Remediation failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rollback/windows")
async def rollback_windows(
    host: str = Form(...),
    username: str = Form("Window"),  # SỬA: "Administrator" → "Window"
    password: str = Form(..., json_schema_extra={"format": "password"}),
    backup_id: Optional[str] = Form(None),
):
    """Rollback Windows system về trạng thái trước khi remediation."""
    try:
        print(f"🔄 Starting rollback for {host} with username: {username}")
        
        session = winrm_connect(host, username, password)
        print("✅ WinRM connection established")
        
        result = rollback_manager.execute_rollback(host, session, backup_id)
        
        return {
            "status": "SUCCESS",
            "message": "Rollback completed successfully",
            "host": host,
            "backup_id": result["backup_id"],
            "rollback_details": result["rollback_details"]
        }
        
    except Exception as e:
        print(f"❌ Rollback failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/backups/windows")
async def get_windows_backups(host: Optional[str] = None):
    """Lấy danh sách backups Windows."""
    try:
        if host:
            backups = rollback_manager.get_backups(host)
        else:
            backups = list(db.backups.find({"os_type": {"$ne": "linux"}}, sort=[("timestamp", -1)]).limit(50))
            for backup in backups:
                backup["_id"] = str(backup["_id"])
        
        return {"total": len(backups), "backups": backups}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rollback/linux")
async def rollback_linux(
    Host: str = Form(...),
    Username: str = Form(""),
    Key_path: Optional[str] = Form("~/.ssh/id_ed25519"),
    Password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    Sudo_password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    backup_id: Optional[str] = Form(None),
):
    """Rollback Linux system về trạng thái trước khi remediation."""
    try:
        print(f"🔄 Starting rollback for Linux host: {Host}")
        
        result = linux_rollback_manager.execute_rollback(
            Host, Username, Key_path or "", Password, Sudo_password, backup_id
        )
        
        return {
            "status": result.get("status", "SUCCESS"),
            "message": result.get("message", "Rollback completed successfully"),
            "host": Host,
            "backup_id": result.get("backup_id"),
            "rollback_details": result.get("rollback_details", {})
        }
        
    except Exception as e:
        print(f"❌ Rollback failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/backups/linux")
async def get_linux_backups(host: Optional[str] = None):
    """Lấy danh sách backups Linux."""
    try:
        if host:
            backups = linux_rollback_manager.get_backups(host)
        else:
            backups = list(db.backups.find({"os_type": "linux"}, sort=[("timestamp", -1)]).limit(50))
            for backup in backups:
                backup["_id"] = str(backup["_id"])
        
        return {"total": len(backups), "backups": backups}
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
    create_backup: bool = Form(True),
):
    """Chạy remediation script để fix rule FAIL - Tự động tạo backup - Lưu log vào MongoDB."""
    try:
        print(f"🔄 Starting Linux remediation for {Host} with rule: {Rule_id}")
        
        # Kết nối SSH để auto-detect OS
        ssh = ssh_connect(Host, Username, Key_path or "", password=Password)
        detected_os = None
        try:
            detected_os = detect_os(ssh)
            if not detected_os:
                raise HTTPException(status_code=400, detail="Không thể phát hiện OS tự động.")
        finally:
            ssh.close()
        
        backup_id = None
        
        # Tạo backup nếu được yêu cầu - KHÔNG BLOCK NẾU LỖI
        if create_backup:
            try:
                print("🔍 Creating backup...")
                backup_id = linux_rollback_manager.create_backup(
                    Host, Username, Key_path or "", Password, Sudo_password
                )
                if backup_id:
                    print(f"✅ Backup created: {backup_id}")
                else:
                    print(f"⚠️ Backup creation returned None (non-critical error)")
            except Exception as backup_error:
                print(f"⚠️ Backup creation failed (non-critical): {backup_error}")
                # KHÔNG RAISE ERROR - tiếp tục remediation
        
        # Load remediation script
        print(f"📄 Loading remediation script for rule: {Rule_id}")
        script_content = load_remediation_script(detected_os, Rule_id)
        if not script_content:
            raise HTTPException(status_code=404, detail=f"Không tìm thấy remediation script cho rule: {Rule_id}")
        
        # Chạy script remediation
        print("🚀 Running remediation script...")
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
        
        print(f"📊 Script result - Exit code: {exec_result['exit_status']}")
        
        # Chuẩn bị dữ liệu remediation để lưu vào MongoDB
        remediation_data = {
            "host": Host,
            "username": Username,
            "os": detected_os,
            "rule_id": Rule_id,
            "client_type": "linux",
            "backup_id": backup_id,
            "status": "SUCCESS" if exec_result["exit_status"] == 0 else "PARTIAL",
            "exit_code": exec_result["exit_status"],
            "stdout": exec_result["stdout"],
            "stderr": exec_result["stderr"],
            "rollback_status": "AVAILABLE" if backup_id else "NO_BACKUP",
            "created_at": datetime.utcnow()
        }
        
        # LƯU VÀO MONGODB
        remediation_id = db.save_remediation_log(remediation_data)
        
        return {
            "remediation_id": remediation_id,
            "rule_id": Rule_id,
            "backup_id": backup_id,
            "status": "SUCCESS" if exec_result["exit_status"] == 0 else "PARTIAL",
            "host": Host,
            "os": detected_os,
            "exit_code": exec_result["exit_status"],
            "stdout": exec_result["stdout"][:1000],  # Truncate để response không quá dài
            "stderr": exec_result["stderr"][:1000],
            "message": f"Remediation script for rule '{Rule_id}' executed successfully",
            "rollback_available": backup_id is not None
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Remediation failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ==================== REPORTING ENDPOINTS ====================

@app.get("/reports/audits")
async def get_audit_reports(
    host: Optional[str] = None,
    limit: int = 50,
    os_type: Optional[str] = None
):
    """
    Lấy danh sách audit reports từ MongoDB.
    
    Collection: audit_reports
    Filter: có thể filter theo host và os_type
    """
    try:
        audits = db.get_audit_reports(host=host, limit=limit)
        
        # Filter by OS type if provided
        if os_type:
            audits = [a for a in audits if a.get("os_type") == os_type]
            
        # Convert ObjectId to string for JSON serialization
        for audit in audits:
            audit["id"] = str(audit["_id"])
            del audit["_id"]
            
        return {
            "total": len(audits),
            "audits": audits
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/remediations")
async def get_remediation_reports(
    host: Optional[str] = None,
    limit: int = 50
):
    """
    Lấy danh sách remediation logs từ MongoDB.
    
    Collection: remediation_logs
    Filter: có thể filter theo host
    """
    try:
        remediations = db.get_remediation_logs(host=host, limit=limit)
        
        for remediation in remediations:
            remediation["id"] = str(remediation["_id"])
            del remediation["_id"]
            
        return {
            "total": len(remediations),
            "remediations": remediations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/hosts")
async def get_hosts_overview():
    """
    Lấy overview của tất cả hosts từ MongoDB.
    
    Collection: audit_reports (aggregation)
    """
    try:
        hosts = db.get_hosts_overview()
        
        for host in hosts:
            host["id"] = str(host["_id"])
            del host["_id"]
            
        return {
            "total_hosts": len(hosts),
            "hosts": hosts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/compliance-stats")
async def get_compliance_statistics():
    """
    Lấy thống kê compliance tổng thể từ MongoDB.
    
    Collection: audit_reports (aggregation)
    """
    try:
        stats = db.get_compliance_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/audits/{audit_id}")
async def get_audit_detail(audit_id: str):
    """
    Lấy chi tiết một audit report cụ thể từ MongoDB.
    
    Collection: audit_reports
    """
    try:
        audit = db.audits.find_one({"audit_id": audit_id})
        if not audit:
            raise HTTPException(status_code=404, detail="Audit report not found")
        
        audit["id"] = str(audit["_id"])
        del audit["_id"]
        
        return audit
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/version")
async def version():
    """Version endpoint."""
    return {"name": "security_hardening", "api": "v1"}
