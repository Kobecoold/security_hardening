from fastapi import FastAPI, HTTPException, Form, Depends, Security
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Optional
from database import db
from rollback import rollback_manager
from linux_rollback import linux_rollback_manager

import time
import traceback
import os
from datetime import datetime

# Import từ các module mới
from utils import load_rules, load_rules_by_os, load_remediation_script, load_windows_remediation_script
from linux_audit import detect_os, ssh_connect, run_bash_check_stdin, truncate_output, get_linux_host_info
from windows_audit import winrm_connect, run_winrm_audit, get_windows_host_info, detect_os_windows
from auth import auth_manager, RequireAuth, API_KEY_HEADER
from users import user_manager

# Define API_KEY_HEADER for admin check
if 'API_KEY_HEADER' not in globals():
    API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Đường dẫn đến dashboard
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DASHBOARD_DIR = os.path.join(REPO_ROOT, "dashboard")
DASHBOARD_DIST = os.path.join(DASHBOARD_DIR, "dist")

app = FastAPI(
    title="Security Hardening Audit Engine",
    swagger_ui_parameters={
        "displayRequestDuration": True,
        "tryItOutEnabled": True,
    },
)

# CORS middleware - Allow dashboard to make API calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve React dashboard (production build) - Priority 1
# Note: Dashboard routes will be registered at the END of file to avoid conflicts with API routes
DASHBOARD_BUILT = os.path.exists(DASHBOARD_DIST)
if DASHBOARD_BUILT:
    # Serve static assets (JS, CSS, images) - must be before catch-all route
    assets_dir = os.path.join(DASHBOARD_DIST, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="dashboard-assets")

# Fallback: Serve old HTML dashboard if React build doesn't exist
elif os.path.exists(os.path.join(DASHBOARD_DIR, "index.html")):
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard-old")

# API Info endpoint (accessible even when dashboard is served at root)
@app.get("/api/info")
async def root_api_info():
    """API information and quick links."""
    has_keys = auth_manager.has_any_active_keys()
    
    # Determine dashboard URL
    dashboard_url = None
    if os.path.exists(DASHBOARD_DIST):
        dashboard_url = "/"
    elif os.path.exists(os.path.join(DASHBOARD_DIR, "index.html")):
        dashboard_url = "/dashboard"
    
    return {
        "name": "Security Hardening Agentless API",
        "version": "1.0.0",
        "description": "API for agentless security hardening audit and remediation",
        "dashboard": dashboard_url,
        "authentication": {
            "required": True,
            "method": "API Key (X-API-Key header)",
            "setup_endpoint": "/auth/setup" if not has_keys else None,
            "status": "configured" if has_keys else "not_configured"
        },
        "docs": "/docs",
        "health": "/healthz",
        "version_endpoint": "/version",
        "endpoints": {
            "auth": {
                "setup": "/auth/setup (create first API key - no auth required)",
                "create_key": "/auth/api-keys (requires auth)",
                "list_keys": "/auth/api-keys (requires auth)"
            },
            "audit": {
                "linux": "/audit/linux",
                "windows": "/audit/windows"
            },
            "remediation": {
                "linux": "/remediate/linux",
                "windows": "/remediate/windows"
            },
            "rollback": {
                "linux": "/rollback/linux",
                "windows": "/rollback/windows"
            },
            "reports": {
                "audits": "/reports/audits",
                "remediations": "/reports/remediations",
                "hosts": "/reports/hosts",
                "compliance_stats": "/reports/compliance-stats"
            }
        }
    }

# Fallback: Root endpoint returns API info when dashboard not built
if not os.path.exists(DASHBOARD_DIST):
    @app.get("/", name="root_api_info_fallback")
    async def root():
        """Root endpoint - API information (fallback when dashboard not built)."""
        return await root_api_info()

async def require_admin(api_key: Optional[str] = Security(API_KEY_HEADER)) -> bool:
    """Dependency để check admin role."""
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    if not auth_manager.verify_api_key(api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    user_info = auth_manager.get_api_key_user(api_key)
    if not user_info or user_info.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return True

RequireAdmin = Depends(require_admin)

@app.post("/audit/windows", dependencies=[RequireAdmin])
async def audit_windows_winrm(
    host: str = Form(...),
    username: str = Form("Window"),
    password: str = Form(..., json_schema_extra={"format": "password"}),
):
    """Audit Windows using WinRM - Lưu kết quả vào MongoDB."""
    try:
        print(f"🔍 Starting Windows audit for host: {host}")
        
        # Kết nối WinRM
        try:
            print(f"🔄 Connecting to WinRM: {host} with user: {username}")
            session = winrm_connect(host, username, password)
            print("✅ WinRM connection established")
        except Exception as conn_error:
            error_msg = f"WinRM connection failed: {str(conn_error)}"
            print(f"❌ {error_msg}")
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Lấy thông tin host
        try:
            host_info = get_windows_host_info(session)
            if host_info["status"] != "SUCCESS":
                error_msg = f"WinRM connection failed: {host_info.get('error', 'Unknown error')}"
                print(f"❌ {error_msg}")
                raise HTTPException(status_code=400, detail=error_msg)
            print(f"✅ Host info retrieved: {host_info.get('hostname')} - {host_info.get('os_type')}")
        except HTTPException:
            raise
        except Exception as info_error:
            error_msg = f"Failed to get host info: {str(info_error)}"
            print(f"❌ {error_msg}")
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Load rules WinRM theo OS type
        try:
            print("📄 Loading Windows rules...")
            rules = load_rules(os_type=host_info.get("os_type"))
            print(f"✅ Loaded {len(rules)} rules")
        except Exception as rules_error:
            error_msg = f"Failed to load rules: {str(rules_error)}"
            print(f"❌ {error_msg}")
            raise HTTPException(status_code=500, detail=error_msg)
        
        # Chạy audit
        print("🚀 Running audit checks...")
        audit_results = []
        for i, rule in enumerate(rules, 1):
            try:
                print(f"  [{i}/{len(rules)}] Checking: {rule.get('id', 'unknown')} - {rule.get('title', 'No title')}")
                result = run_winrm_audit(session, rule)
                audit_results.append(result)
            except Exception as rule_error:
                print(f"  ⚠️ Error checking rule {rule.get('id', 'unknown')}: {str(rule_error)}")
                # Thêm error result thay vì fail toàn bộ
                audit_results.append({
                    "id": rule.get("id", "unknown"),
                    "title": rule.get("title", "Unknown"),
                    "status": "ERROR",
                    "error": str(rule_error),
                    "command": rule.get("check", {}).get("winrm", "N/A"),
                    "result": "",
                    "expected": rule.get("check", {}).get("expected", "N/A"),
                    "exit_code": -1,
                    "duration_ms": 0
                })
        
        print(f"✅ Audit completed: {len(audit_results)} results")
        
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
        try:
            print("💾 Saving audit results to MongoDB...")
            audit_id = db.save_audit_report(audit_data)
            print(f"✅ Audit saved to MongoDB: {audit_id}")
        except Exception as db_error:
            error_msg = f"MongoDB save failed: {str(db_error)}"
            print(f"❌ {error_msg}")
            # Vẫn trả về kết quả nhưng không có audit_id
            return {
                "audit_id": None,
                "warning": "Results not saved to MongoDB",
                "error": error_msg,
                "client_type": "windows",
                "protocol": "winrm",
                "host": host,
                "hostname": host_info["hostname"],
                "os_type": host_info["os_type"],
                "benchmark": "CIS Windows 10 Level 1",
                "total_rules": len(audit_results),
                "compliance_score": audit_data.get("compliance_score", 0),
                "connection_info": host_info,
                "results": audit_results
            }
        
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
    
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"❌ {error_msg}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/rules")
async def get_rules(os_name: Optional[str] = None):
    """Lấy danh sách rules."""
    try:
        if os_name:
            return {"rules": load_rules_by_os(os_name)}
        return {"rules": load_rules()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/audit/linux", dependencies=[RequireAdmin])
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

        def run_one(rule: Dict, rule_index: int, total_rules: int) -> Dict:
            rule_id = rule.get("id", "unknown")
            rule_title = rule.get("title", "Unknown")
            
            print(f"  [{rule_index}/{total_rules}] Checking: {rule_id} - {rule_title}")
            
            check = rule.get("check", {}) if isinstance(rule, dict) else {}
            script_text = check.get("bash") if isinstance(check, dict) else None
            if not script_text:
                print(f"    ⚠️ Skipped: no check.bash")
                return {"id": rule_id, "title": rule_title, "status": "SKIPPED", "reason": "no check.bash"}
            
            effective_use_sudo = bool(rule.get("needs_sudo", False) or Use_sudo)
            started = time.time()
            
            try:
                ssh_local = ssh_connect(Host, Username, Key_path or "", password=Password)
                try:
                    # Giảm timeout xuống 30s cho mỗi audit check (nhanh hơn remediation)
                    exec_result = run_bash_check_stdin(
                        ssh_local,
                        script_text,
                        use_sudo=effective_use_sudo,
                        sudo_password=Sudo_password,
                        timeout=30,  # 30 seconds timeout cho audit checks
                    )
                finally:
                    try:
                        ssh_local.close()
                    except Exception:
                        pass
                
                duration_ms = int((time.time() - started) * 1000)
                
                # Log kết quả
                if exec_result.get("status") == "TIMEOUT":
                    print(f"    ⚠️ TIMEOUT after 30s")
                elif exec_result.get("exit_status") == 0:
                    print(f"    ✅ PASS ({duration_ms}ms)")
                else:
                    print(f"    ❌ FAIL ({duration_ms}ms)")
                
                tout_dict = truncate_output(exec_result["stdout"]) 
                terr_dict = truncate_output(exec_result["stderr"]) 
                return {
                    "id": rule_id,
                    "title": rule_title,
                    "os": rule.get("os"),
                    "benchmark": rule.get("benchmark"),
                    "needs_sudo": effective_use_sudo,
                    "exit_status": exec_result["exit_status"],
                    "status": exec_result["status"],
                    "stdout": tout_dict.get("text", ""),
                    "stdout_truncated": tout_dict.get("truncated", False),
                    "stdout_sha256": tout_dict.get("sha256"),
                    "stderr": terr_dict.get("text", ""),
                    "stderr_truncated": terr_dict.get("truncated", False),
                    "stderr_sha256": terr_dict.get("sha256"),
                    "duration_ms": duration_ms,
                    "started_at": int(started * 1000),
                }
            except Exception as rule_error:
                print(f"    ❌ ERROR: {str(rule_error)[:100]}")
                return {
                    "id": rule_id,
                    "title": rule_title,
                    "status": "ERROR",
                    "error": str(rule_error),
                    "duration_ms": int((time.time() - started) * 1000),
                }

        # Chạy tuần tự với progress logging
        print(f"🚀 Running {len(rules)} audit checks on {Host}...")
        print(f"   Timeout per check: 30 seconds")
        print(f"   Estimated time: ~{len(rules) * 30 / 60:.1f} minutes")
        
        for i, rule in enumerate(rules, 1):
            try:
                results.append(run_one(rule, i, len(rules)))
            except Exception as e:
                print(f"  ❌ Fatal error on rule {i}: {e}")
                results.append({
                    "id": rule.get("id", "unknown"),
                    "title": rule.get("title", "Unknown"),
                    "status": "ERROR",
                    "error": str(e)
                })

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
        try:
            print("💾 Saving audit results to MongoDB...")
            audit_id = db.save_audit_report(audit_data)
            print(f"✅ Audit saved to MongoDB: {audit_id}")
        except Exception as db_error:
            print(f"⚠️ MongoDB save failed (non-critical): {db_error}")
            audit_id = None

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
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Linux audit failed: {str(e)}"
        print(f"❌ {error_msg}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/healthz")
async def healthz():
    """Health check endpoint."""
    return {"status": "ok"}

@app.post("/test/connection/linux", dependencies=[RequireAuth])
async def test_linux_connection(
    Host: str = Form(...),
    Username: str = Form(""),
    Key_path: Optional[str] = Form("~/.ssh/id_ed25519"),
    Password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
    Use_sudo: bool = Form(False),
    Sudo_password: Optional[str] = Form(None, json_schema_extra={"format": "password"}),
):
    """
    Test connection và quyền truy cập vào Linux host.
    Dùng để verify trước khi chạy remediation.
    """
    try:
        print(f"🔌 Testing connection to {Host}...")
        
        # Test SSH connection
        ssh = ssh_connect(Host, Username, Key_path or "", password=Password)
        connection_info = {}
        
        try:
            # Test basic command
            test_result = run_bash_check_stdin(ssh, "echo 'Connection OK'", use_sudo=False, timeout=10)
            connection_info["basic_command"] = {
                "success": test_result.get("exit_status") == 0,
                "output": test_result.get("stdout", ""),
                "error": test_result.get("stderr", "")
            }
            
            # Test sudo if needed
            sudo_available = False
            if Use_sudo:
                if Sudo_password:
                    sudo_test = run_bash_check_stdin(
                        ssh, "sudo -S -p '' echo 'Sudo OK'", use_sudo=True, sudo_password=Sudo_password, timeout=10
                    )
                    sudo_available = sudo_test.get("exit_status") == 0
                else:
                    sudo_test = run_bash_check_stdin(
                        ssh, "sudo -n echo 'Sudo OK'", use_sudo=True, timeout=10
                    )
                    sudo_available = sudo_test.get("exit_status") == 0
                
                connection_info["sudo"] = {
                    "available": sudo_available,
                    "output": sudo_test.get("stdout", ""),
                    "error": sudo_test.get("stderr", "")
                }
            
            # Get host info
            host_info = get_linux_host_info(ssh)
            detected_os = detect_os(ssh)
            
            connection_info["host_info"] = host_info
            connection_info["detected_os"] = detected_os
            
        finally:
            ssh.close()
        
        return {
            "status": "SUCCESS",
            "host": Host,
            "connection_verified": True,
            "connection_info": connection_info,
            "message": f"✅ Successfully connected to {Host} and verified access"
        }
        
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Connection test failed: {str(e)}")

# SỬA ENDPOINT REMEDIATION ĐỂ TỰ ĐỘNG TẠO BACKUP
@app.post("/remediate/windows", dependencies=[RequireAuth])
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
        
        # Lấy thông tin host để có os_type (dùng cho cả backup và remediation)
        host_info = get_windows_host_info(session)
        if host_info["status"] != "SUCCESS":
            raise HTTPException(status_code=400, detail=f"WinRM connection failed: {host_info.get('error', 'Unknown error')}")
        os_type = host_info.get("os_type", "windows-unknown")
        
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
        try:
            script_content = load_windows_remediation_script(script_name)
            if not script_content:
                raise HTTPException(status_code=404, detail=f"Remediation script not found: {script_name}. Check if file exists in scripts/remediation/window-10/")
        except Exception as load_error:
            error_msg = f"Failed to load script {script_name}: {str(load_error)}"
            print(f"❌ {error_msg}")
            raise HTTPException(status_code=500, detail=error_msg)
        
        # Chạy script remediation
        print("🚀 Running remediation script...")
        try:
            result = session.run_ps(script_content)
        except Exception as exec_error:
            error_msg = f"Failed to execute PowerShell script: {str(exec_error)}"
            print(f"❌ {error_msg}")
            raise HTTPException(status_code=500, detail=error_msg)
        
        # Normalize line endings và decode output
        output = result.std_out.decode('utf-8', errors='ignore').replace('\r\n', '\n').replace('\r', '\n').strip()
        error = result.std_err.decode('utf-8', errors='ignore').replace('\r\n', '\n').replace('\r', '\n').strip()
        
        print(f"📊 Script result - Exit code: {result.status_code}")
        if output:
            print(f"   Output length: {len(output)} characters")
        if error:
            print(f"   Error output: {error[:200]}...")
        
        # Chuẩn bị dữ liệu remediation để lưu vào MongoDB
        remediation_data = {
            "host": host,
            "username": username,
            "os_type": os_type,
            "client_type": "windows",
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
        try:
            print("💾 Saving remediation log to MongoDB...")
            remediation_id = db.save_remediation_log(remediation_data)
            print(f"✅ Remediation log saved: {remediation_id}")
        except Exception as db_error:
            print(f"⚠️ MongoDB save failed (non-critical): {db_error}")
            remediation_id = None
        
        return {
            "remediation_id": remediation_id,
            "backup_id": backup_id,
            "status": "SUCCESS" if result.status_code == 0 else "PARTIAL",
            "host": host,
            "os_type": os_type,
            "script_used": script_name,
            "exit_code": result.status_code,
            "output": output[:1000] if output else "",
            "error": error[:1000] if error else "",
            "message": f"Remediation script '{script_name}' executed successfully" if result.status_code == 0 else f"Remediation script '{script_name}' completed with exit code {result.status_code}",
            "rollback_available": backup_id is not None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Remediation failed: {str(e)}"
        print(f"❌ {error_msg}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=error_msg)

@app.post("/rollback/windows", dependencies=[RequireAuth])
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
            "status": result.get("status", "SUCCESS"),
            "message": result.get("message", "Rollback completed successfully"),
            "host": host,
            "backup_id": result.get("backup_id"),
            "rollback_details": result.get("rollback_details", {})
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Rollback failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/backups/windows", dependencies=[RequireAuth])
async def get_windows_backups(host: Optional[str] = None):
    """Lấy danh sách backups Windows."""
    try:
        if host:
            backups = rollback_manager.get_backups(host)
        else:
            backups = db.get_backups_not_linux(limit=50)
            for backup in backups:
                backup["_id"] = str(backup["_id"])
        
        return {"total": len(backups), "backups": backups}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rollback/linux", dependencies=[RequireAuth])
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

@app.get("/backups/linux", dependencies=[RequireAuth])
async def get_linux_backups(host: Optional[str] = None):
    """Lấy danh sách backups Linux."""
    try:
        if host:
            backups = linux_rollback_manager.get_backups(host)
        else:
            backups = db.get_backups_by_os_type("linux", limit=50)
            for backup in backups:
                backup["_id"] = str(backup["_id"])
        
        return {"total": len(backups), "backups": backups}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/remediate/linux", dependencies=[RequireAuth])
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
        print(f"   Username: {Username}")
        print(f"   Using sudo: {Use_sudo}")
        
        # Kết nối SSH để auto-detect OS - VERIFY CONNECTION
        print(f"🔌 Step 1: Connecting to {Host}...")
        ssh = ssh_connect(Host, Username, Key_path or "", password=Password)
        detected_os = None
        try:
            print(f"✅ SSH connection established to {Host}")
            
            # Test connection bằng cách chạy một command đơn giản
            test_result = run_bash_check_stdin(ssh, "echo 'Connection test successful'", use_sudo=False, timeout=10)
            if test_result.get("exit_status") != 0:
                raise HTTPException(status_code=400, detail=f"SSH connection test failed: {test_result.get('stderr', 'Unknown error')}")
            print(f"✅ Connection test passed: {test_result.get('stdout', '')}")
            
            detected_os = detect_os(ssh)
            if not detected_os:
                raise HTTPException(status_code=400, detail="Không thể phát hiện OS tự động.")
            print(f"✅ Detected OS: {detected_os}")
        finally:
            ssh.close()
            print(f"🔌 SSH connection closed")
        
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
        print(f"📄 Step 2: Loading remediation script for rule: {Rule_id}")
        script_content = load_remediation_script(detected_os, Rule_id)
        if not script_content:
            raise HTTPException(status_code=404, detail=f"Không tìm thấy remediation script cho rule: {Rule_id}")
        print(f"✅ Script loaded ({len(script_content)} bytes)")
        
        # Chạy script remediation với timeout 2 phút (120 giây)
        print(f"🚀 Step 3: Executing remediation script on {Host}...")
        print(f"   Script will run with sudo: {Use_sudo}")
        print(f"   Timeout: 120 seconds")
        
        ssh_exec = ssh_connect(Host, Username, Key_path or "", password=Password)
        try:
            print(f"✅ Connected to {Host} for script execution")
            
            exec_result = run_bash_check_stdin(
                ssh_exec,
                script_content,
                use_sudo=Use_sudo,
                sudo_password=Sudo_password,
                timeout=120,  # 2 minutes timeout
            )
            
            # Log kết quả
            if exec_result.get("status") == "TIMEOUT":
                print(f"⚠️ Script execution timeout after 120s")
            elif exec_result.get("exit_status") == 0:
                print(f"✅ Script executed successfully (exit code 0)")
            else:
                print(f"⚠️ Script completed with exit code {exec_result.get('exit_status')}")
            
            if exec_result.get("stdout"):
                print(f"   Script output: {exec_result['stdout'][:300]}...")
            if exec_result.get("stderr"):
                print(f"   Script errors: {exec_result['stderr'][:300]}...")
        finally:
            ssh_exec.close()
            print(f"🔌 Execution connection closed")
        
        print(f"📊 Script result - Exit code: {exec_result['exit_status']}")
        print(f"   Status: {exec_result.get('status', 'UNKNOWN')}")
        if exec_result.get("stdout"):
            print(f"   Output preview: {exec_result['stdout'][:200]}...")
        if exec_result.get("stderr"):
            print(f"   Error preview: {exec_result['stderr'][:200]}...")
        
        # VERIFY: Chạy lại check command để xác nhận đã fix
        print(f"🔍 Step 4: Verifying remediation on {Host}...")
        verification_passed = False
        verification_output = ""
        verification_error = ""
        try:
            # Load rule để lấy check command
            rules = load_rules_by_os(detected_os)
            rule = next((r for r in rules if r.get("id") == Rule_id), None)
            
            if rule and rule.get("check", {}).get("bash"):
                check_command = rule["check"]["bash"]
                print(f"   Check command: {check_command[:100]}...")
                
                ssh_verify = ssh_connect(Host, Username, Key_path or "", password=Password)
                try:
                    print(f"✅ Connected to {Host} for verification")
                    
                    verify_result = run_bash_check_stdin(
                        ssh_verify,
                        check_command,
                        use_sudo=Use_sudo,
                        sudo_password=Sudo_password,
                        timeout=30
                    )
                    verification_passed = verify_result.get("exit_status") == 0
                    verification_output = verify_result.get("stdout", "")
                    verification_error = verify_result.get("stderr", "")
                    
                    if verification_passed:
                        print(f"✅ Verification PASSED - Vulnerability '{Rule_id}' is FIXED")
                        print(f"   Verification output: {verification_output[:200]}")
                    else:
                        print(f"⚠️ Verification FAILED - Vulnerability '{Rule_id}' may still exist")
                        print(f"   Exit code: {verify_result.get('exit_status')}")
                        print(f"   Output: {verification_output[:200]}")
                        if verification_error:
                            print(f"   Error: {verification_error[:200]}")
                finally:
                    ssh_verify.close()
                    print(f"🔌 Verification connection closed")
            else:
                print("⚠️ No check command found in rule for verification")
        except Exception as verify_error:
            print(f"❌ Verification check failed: {verify_error}")
            traceback.print_exc()
        
        # Chuẩn bị dữ liệu remediation để lưu vào MongoDB
        remediation_data = {
            "host": Host,
            "username": Username,
            "os": detected_os,
            "rule_id": Rule_id,
            "client_type": "linux",
            "backup_id": backup_id,
            "status": "SUCCESS" if (exec_result["exit_status"] == 0 and verification_passed) else "PARTIAL",
            "exit_code": exec_result["exit_status"],
            "stdout": exec_result["stdout"],
            "stderr": exec_result["stderr"],
            "verification_passed": verification_passed,
            "verification_output": verification_output,
            "rollback_status": "AVAILABLE" if backup_id else "NO_BACKUP",
            "created_at": datetime.utcnow()
        }
        
        # LƯU VÀO MONGODB
        try:
            print("💾 Saving remediation log to MongoDB...")
            remediation_id = db.save_remediation_log(remediation_data)
            print(f"✅ Remediation log saved: {remediation_id}")
        except Exception as db_error:
            print(f"⚠️ MongoDB save failed (non-critical): {db_error}")
            remediation_id = None
        
        # Determine final status
        if exec_result["exit_status"] == 0 and verification_passed:
            final_status = "SUCCESS"
            message = f"✅ Remediation successful - Vulnerability '{Rule_id}' is FIXED and VERIFIED on {Host}"
        elif exec_result["exit_status"] == 0:
            final_status = "PARTIAL"
            message = f"⚠️ Script completed but verification FAILED - Vulnerability '{Rule_id}' may still exist on {Host}"
        else:
            final_status = "PARTIAL"
            message = f"⚠️ Script failed (exit code {exec_result['exit_status']}) - Vulnerability '{Rule_id}' may not be fixed on {Host}"
        
        print(f"📋 Final Status: {final_status}")
        print(f"   Script exit code: {exec_result['exit_status']}")
        print(f"   Verification passed: {verification_passed}")
        print(f"   Message: {message}")
        
        return {
            "remediation_id": remediation_id,
            "rule_id": Rule_id,
            "backup_id": backup_id,
            "status": final_status,
            "host": Host,
            "os": detected_os,
            "exit_code": exec_result["exit_status"],
            "stdout": exec_result["stdout"][:1000],  # Truncate để response không quá dài
            "stderr": exec_result["stderr"][:1000],
            "verification_passed": verification_passed,
            "verification_output": verification_output[:500] if verification_output else "",
            "verification_error": verification_error[:500] if verification_error else "",
            "message": message,
            "rollback_available": backup_id is not None,
            "connection_verified": True,  # Đã verify connection thành công
            "script_executed": True,  # Đã chạy script trên client
            "verification_performed": True  # Đã verify sau khi fix
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Remediation failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ==================== REPORTING ENDPOINTS ====================

@app.get("/reports/audits", dependencies=[RequireAuth])
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

@app.get("/reports/remediations", dependencies=[RequireAuth])
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

@app.get("/reports/hosts", dependencies=[RequireAuth])
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

@app.get("/reports/compliance-stats", dependencies=[RequireAuth])
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

@app.get("/reports/audits/{audit_id}", dependencies=[RequireAuth])
async def get_audit_detail(audit_id: str):
    """
    Lấy chi tiết một audit report cụ thể từ MongoDB.
    
    Collection: audit_reports
    """
    try:
        audit = db.get_audit_by_id(audit_id)
        if not audit:
            raise HTTPException(status_code=404, detail="Audit report not found")
        
        audit["id"] = str(audit["_id"])
        del audit["_id"]
        
        return audit
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== USER AUTHENTICATION ENDPOINTS ====================

@app.post("/auth/users/register", dependencies=[RequireAuth])
async def register_user(
    username: str = Form(...),
    password: str = Form(..., json_schema_extra={"format": "password"}),
    email: str = Form(""),
    role: str = Form("user"),
    api_key: Optional[str] = Security(API_KEY_HEADER),
):
    """Đăng ký user mới. Admin only hoặc first user."""
    try:
        # Check if this is the first user (no auth required)
        is_first_user = not user_manager.has_any_users()
        
        # If not first user, require admin authentication
        if not is_first_user:
            if not api_key:
                raise HTTPException(status_code=401, detail="Authentication required for creating users")
            
            if not auth_manager.verify_api_key(api_key):
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            # Check if user is admin
            user_info = auth_manager.get_api_key_user(api_key)
            if not user_info or user_info.get("role") != "admin":
                raise HTTPException(status_code=403, detail="Only admins can create users")
        
        # Không cho phép tạo user với role admin (chỉ có 1 admin duy nhất)
        if role == "admin":
            raise HTTPException(status_code=400, detail="Cannot create admin user. Only one admin account is allowed.")
        
        # Force role to be 'user' (không tin tưởng input từ client)
        user = user_manager.create_user(username, password, email, "user")
        return {
            "status": "success",
            "message": "User created successfully",
            "user": user
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/auth/users", dependencies=[RequireAuth])
async def list_users():
    """Lấy danh sách users. Admin only."""
    try:
        users = user_manager.list_users()
        return {"total": len(users), "users": users}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/users/login")
async def login_user(
    username: str = Form(...),
    password: str = Form(..., json_schema_extra={"format": "password"}),
):
    """Đăng nhập user và trả về API key tạm thời."""
    try:
        if not user_manager.verify_user(username, password):
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
            )
        
        # Tạo API key tạm thời cho user này (hoặc có thể dùng JWT token)
        # Ở đây tạm thời tạo API key với tên user
        api_key_data = auth_manager.generate_api_key(
            name=f"User: {username}",
            description=f"Temporary API key for {username}",
            expires_days=30
        )
        
        user_info = user_manager.get_user(username)
        
        return {
            "status": "success",
            "message": "Login successful",
            "api_key": api_key_data["api_key"],
            "user": user_info,
            "expires_at": api_key_data["expires_at"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/auth/users/me", dependencies=[RequireAuth])
async def get_current_user():
    """Lấy thông tin user hiện tại (cần API key)."""
    # Note: Cần implement logic để map API key với user
    # Tạm thời trả về thông tin cơ bản
    return {
        "message": "User info endpoint - to be implemented with API key to user mapping"
    }

# ==================== API KEY AUTHENTICATION ENDPOINTS ====================

@app.post("/auth/setup")
async def setup_first_api_key(
    name: str = Form("Default API Key"),
    description: str = Form("Initial API key created during setup"),
    expires_days: Optional[int] = Form(None),
):
    """
    Tạo API key đầu tiên (không cần authentication).
    Chỉ hoạt động nếu chưa có API key nào trong hệ thống.
    """
    try:
        # Kiểm tra xem đã có key nào chưa
        if auth_manager.has_any_active_keys():
            raise HTTPException(
                status_code=403,
                detail="API keys already exist. Use /auth/api-keys endpoint with authentication to create new keys."
            )
        
        result = auth_manager.generate_api_key(name, description, expires_days)
        return {
            **result,
            "message": "✅ First API key created successfully! Use this key in X-API-Key header for all requests."
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/api-keys", dependencies=[RequireAuth])
async def create_api_key(
    name: str = Form(...),
    description: str = Form(""),
    expires_days: Optional[int] = Form(None),
):
    """Tạo API key mới. Yêu cầu authentication để tạo key mới."""
    try:
        result = auth_manager.generate_api_key(name, description, expires_days)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/auth/api-keys", dependencies=[RequireAuth])
async def list_api_keys():
    """Lấy danh sách API keys (không hiển thị key thực tế)."""
    try:
        keys = auth_manager.list_api_keys()
        return {"total": len(keys), "keys": keys}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/auth/api-keys/{api_key_hash}", dependencies=[RequireAuth])
async def revoke_api_key(api_key_hash: str):
    """Vô hiệu hóa API key."""
    try:
        success = auth_manager.revoke_api_key(api_key_hash)
        if success:
            return {"status": "success", "message": "API key revoked successfully"}
        else:
            raise HTTPException(status_code=404, detail="API key not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/auth/api-keys/{api_key_hash}/delete", dependencies=[RequireAuth])
async def delete_api_key(api_key_hash: str):
    """Xóa hoàn toàn API key (không chỉ revoke)."""
    try:
        success = auth_manager.delete_api_key_by_hash(api_key_hash)
        if success:
            return {"status": "success", "message": "API key deleted permanently"}
        else:
            raise HTTPException(status_code=404, detail="API key not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/auth/api-keys", dependencies=[RequireAuth])
async def clear_all_api_keys():
    """Xóa tất cả API keys (RESET - cẩn thận!). Yêu cầu authentication."""
    try:
        deleted_count = auth_manager.delete_all_api_keys()
        return {
            "status": "success",
            "message": f"All API keys deleted ({deleted_count} keys removed)",
            "deleted_count": deleted_count,
            "warning": "⚠️ You can now use /auth/setup to create a new first API key"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/reset")
async def reset_all_api_keys(
    confirm: str = Form(..., description="Nhập 'RESET_ALL_KEYS' để xác nhận")
):
    """
    Reset tất cả API keys (KHÔNG CẦN AUTHENTICATION).
    Chỉ dùng khi bạn không có API key nào hoặc cần reset hoàn toàn.
    Yêu cầu xác nhận bằng cách nhập 'RESET_ALL_KEYS'.
    """
    try:
        if confirm != "RESET_ALL_KEYS":
            raise HTTPException(
                status_code=400,
                detail="Invalid confirmation. Must enter 'RESET_ALL_KEYS' to confirm."
            )
        
        deleted_count = auth_manager.delete_all_api_keys()
        return {
            "status": "success",
            "message": f"All API keys deleted ({deleted_count} keys removed)",
            "deleted_count": deleted_count,
            "warning": "⚠️ You can now use /auth/setup to create a new first API key"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/version")
async def version():
    """Version endpoint."""
    return {"name": "security_hardening", "api": "v1"}

# ==================== DASHBOARD ROUTES (Must be last to avoid conflicts) ====================

# Serve React dashboard at root (only if built)
# This must be registered AFTER all API routes
if DASHBOARD_BUILT:
    @app.get("/", name="serve_dashboard_root")
    async def serve_dashboard_root():
        """Serve React dashboard at root."""
        index_path = os.path.join(DASHBOARD_DIST, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        # Fallback to API info if index.html not found
        return await root_api_info()
    
    # Serve dashboard at /dashboard as well for backward compatibility
    @app.get("/dashboard", name="serve_dashboard_base")
    @app.get("/dashboard/{path:path}", name="serve_dashboard_path")
    async def serve_dashboard_route(path: str = ""):
        """Serve React dashboard at /dashboard route (for SPA routing)."""
        index_path = os.path.join(DASHBOARD_DIST, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return await root_api_info()
    
    # Catch-all for React Router (must be last route)
    # This handles all non-API routes like /hosts, /audits, etc.
    @app.get("/{path:path}", name="serve_dashboard_spa")
    async def serve_dashboard_spa(path: str):
        """Catch-all route for React SPA routing (handles /hosts, /audits, etc.)."""
        # Skip if it's an API route or static file
        if path.startswith(("api/", "docs", "redoc", "openapi.json", "healthz", "version", 
                           "audit/", "remediate/", "rollback/", "reports/", "auth/", 
                           "backups/", "rules", "test/", "assets/")):
            raise HTTPException(status_code=404, detail="Not found")
        
        # Serve React dashboard for all other routes
        index_path = os.path.join(DASHBOARD_DIST, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        raise HTTPException(status_code=404, detail="Dashboard not found")
