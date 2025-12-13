"""Rollback module for Windows security hardening."""
import json
from datetime import datetime
from typing import Dict, Optional, List, Any
import winrm
from database import db
from windows_audit import winrm_connect
import re

class RollbackManager:
    """Quản lý rollback cho Windows."""
    
    def __init__(self):
        self.db = db
    
    def create_backup(self, host: str, session: winrm.Session) -> str:
        """Tạo backup trạng thái hiện tại trước khi remediation."""
        try:
            print(f"🛡️ Starting backup for {host}")
            
            # Kiểm tra connection trước
            test_result = session.run_cmd('echo Backup Test')
            if test_result.status_code != 0:
                print(f"⚠️ Connection test failed: {test_result.std_err.decode()}")
            
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "pre_remediation_backup",
                "os_type": "windows",
                "backup_id": f"backup_{int(datetime.utcnow().timestamp())}",
                "data": {}
            }
            
            # 1. Backup Password Policy (CHỈ ĐỌC, KHÔNG THAY ĐỔI)
            # WinRM có timeout mặc định ~30s, các commands này thường nhanh (<5s)
            try:
                print("🔍 Backing up password policy...")
                net_result = session.run_cmd('net accounts')
                if net_result.status_code == 0:
                    net_output = net_result.std_out.decode().strip()
                    backup_data["data"]["password_policy"] = self._parse_net_accounts(net_output)
                    print(f"   ✓ Password policy backed up")
                else:
                    print(f"   ⚠️ Failed to get password policy (skipped)")
            except Exception as e:
                print(f"   ⚠️ Error backing up password policy (skipped): {e}")
            
            # 2. Backup Remote Assistance
            try:
                print("🔍 Backing up remote assistance setting...")
                reg_result = session.run_cmd('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" /v fAllowToGetHelp')
                if reg_result.status_code == 0:
                    reg_output = reg_result.std_out.decode().strip()
                    if "0x0" in reg_output:
                        backup_data["data"]["remote_assistance"] = 0
                    else:
                        backup_data["data"]["remote_assistance"] = 1
                    print(f"   ✓ Remote assistance backed up")
                else:
                    backup_data["data"]["remote_assistance"] = 1
                    print(f"   ⚠️ Failed to get remote assistance (using default)")
            except Exception as e:
                print(f"   ⚠️ Error backing up remote assistance (using default): {e}")
                backup_data["data"]["remote_assistance"] = 1
            
            # 3. Backup Administrator Account Status
            try:
                print("🔍 Backing up administrator account status...")
                admin_result = session.run_cmd('net user Administrator')
                if admin_result.status_code == 0:
                    admin_output = admin_result.std_out.decode().strip()
                    if "Account active" in admin_output and "Yes" in admin_output:
                        backup_data["data"]["admin_account_active"] = True
                    else:
                        backup_data["data"]["admin_account_active"] = False
                    print(f"   ✓ Administrator account status backed up")
                else:
                    backup_data["data"]["admin_account_active"] = True
                    print(f"   ⚠️ Failed to get admin status (using default)")
            except Exception as e:
                print(f"   ⚠️ Error backing up admin account (using default): {e}")
                backup_data["data"]["admin_account_active"] = True
            
            # 4. Backup Audit Policy
            try:
                print("🔍 Backing up audit policy...")
                audit_result = session.run_cmd('auditpol /get /subcategory:"Logon"')
                if audit_result.status_code == 0:
                    audit_output = audit_result.std_out.decode().strip()
                    backup_data["data"]["audit_logon"] = self._parse_audit_policy(audit_output)
                    print(f"   ✓ Audit policy backed up")
                else:
                    backup_data["data"]["audit_logon"] = {"success": "No Auditing", "failure": "No Auditing"}
                    print(f"   ⚠️ Failed to get audit policy (using default)")
            except Exception as e:
                print(f"   ⚠️ Error backing up audit policy (using default): {e}")
                backup_data["data"]["audit_logon"] = {"success": "No Auditing", "failure": "No Auditing"}
            
            # Thêm thông tin cơ bản về backup
            backup_data["data"]["backup_info"] = {
                "backup_time": str(datetime.utcnow()),
                "host": host,
                "notes": "Backup created before remediation - Only security policy settings",
                "backup_scope": "Limited - Security policies only (NOT full system backup)"
            }
            
            # Save to MongoDB
            backup_id = self._save_backup(backup_data)
            print(f"✅ Backup created for {host}: {backup_id}")
            
            return backup_id
            
        except Exception as e:
            print(f"❌ Backup creation failed: {e}")
            # Không raise exception để remediation vẫn chạy được
            return None
    
    def _parse_net_accounts(self, output: str) -> Dict[str, Any]:
        """Parse net accounts output."""
        settings = {
            "min_password_length": 0,
            "lockout_threshold": 0,
        }
        
        try:
            lines = output.split('\n')
            for line in lines:
                if "Minimum password length" in line:
                    match = re.search(r'Minimum password length:\s+(\d+)', line)
                    if match:
                        settings["min_password_length"] = int(match.group(1))
                elif "Lockout threshold" in line:
                    match = re.search(r'Lockout threshold:\s+(\d+)', line)
                    if match:
                        settings["lockout_threshold"] = int(match.group(1))
        except:
            pass
        
        return settings
    
    def _parse_audit_policy(self, output: str) -> Dict[str, str]:
        """Parse audit policy output."""
        settings = {"success": "No Auditing", "failure": "No Auditing"}
        
        try:
            lines = output.split('\n')
            for line in lines:
                if "Logon" in line:
                    if "Success" in line:
                        settings["success"] = "Success"
                    if "Failure" in line:
                        settings["failure"] = "Failure"
        except:
            pass
        
        return settings
    
    def _save_backup(self, backup_data: Dict) -> str:
        """Lưu backup vào MongoDB."""
        try:
            result = self.db.backups.insert_one(backup_data)
            return str(result.inserted_id)
        except Exception as e:
            print(f"❌ Failed to save backup to MongoDB: {e}")
            return f"backup_error_{int(datetime.utcnow().timestamp())}"
    
    def execute_rollback(self, host: str, session: winrm.Session, backup_id: Optional[str] = None) -> Dict:
        """Thực hiện rollback dựa trên backup."""
        try:
            # Tìm backup
            if backup_id:
                backup = self.db.backups.find_one({"backup_id": backup_id, "host": host})
            else:
                backup = self.db.backups.find_one(
                    {"host": host, "type": "pre_remediation_backup"},
                    sort=[("timestamp", -1)]
                )
            
            if not backup:
                return {
                    "status": "SKIPPED",
                    "message": f"No backup found for host {host}",
                    "host": host
                }
            
            print(f"🔄 Starting rollback for {host} using backup: {backup['backup_id']}")
            
            rollback_details = {}
            
            # 1. Khôi phục Password Policy nếu có
            if "password_policy" in backup["data"]:
                policy = backup["data"]["password_policy"]
                
                if policy.get("min_password_length", 0) > 0:
                    cmd = f'net accounts /minpwlen:{policy["min_password_length"]}'
                    result = session.run_cmd(cmd)
                    rollback_details["password_min_length"] = {
                        "command": cmd,
                        "result": result.std_out.decode(),
                        "exit_code": result.status_code
                    }
                
                if policy.get("lockout_threshold", -1) >= 0:
                    cmd = f'net accounts /lockoutthreshold:{policy["lockout_threshold"]}'
                    result = session.run_cmd(cmd)
                    rollback_details["account_lockout"] = {
                        "command": cmd,
                        "result": result.std_out.decode(),
                        "exit_code": result.status_code
                    }
            
            # 2. Khôi phục Remote Assistance nếu có
            if "remote_assistance" in backup["data"]:
                value = backup["data"]["remote_assistance"]
                cmd = f'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d {value} /f'
                result = session.run_cmd(cmd)
                rollback_details["remote_assistance"] = {
                    "command": cmd,
                    "result": result.std_out.decode(),
                    "exit_code": result.status_code
                }
            
            # 3. Khôi phục Administrator Account nếu có
            if "admin_account_active" in backup["data"]:
                value = "yes" if backup["data"]["admin_account_active"] else "no"
                cmd = f'net user Administrator /active:{value}'
                result = session.run_cmd(cmd)
                rollback_details["admin_account"] = {
                    "command": cmd,
                    "result": result.std_out.decode(),
                    "exit_code": result.status_code
                }
            
            # 4. Khôi phục Audit Policy nếu có
            if "audit_logon" in backup["data"]:
                audit = backup["data"]["audit_logon"]
                success = "enable" if audit["success"] == "Success" else "disable"
                failure = "enable" if audit["failure"] == "Failure" else "disable"
                cmd = f'auditpol /set /subcategory:"Logon" /success:{success} /failure:{failure}'
                result = session.run_cmd(cmd)
                rollback_details["audit_policy"] = {
                    "command": cmd,
                    "result": result.std_out.decode(),
                    "exit_code": result.status_code
                }
            
            # Lưu rollback log
            rollback_log = {
                "host": host,
                "backup_id": backup["backup_id"],
                "timestamp": datetime.utcnow(),
                "type": "rollback_executed",
                "rollback_details": rollback_details,
                "status": "SUCCESS"
            }
            
            self.db.backups.insert_one(rollback_log)
            self._update_remediation_status(host, "ROLLED_BACK")
            
            return {
                "status": "SUCCESS",
                "message": f"Rollback completed for {host}",
                "backup_id": backup["backup_id"],
                "rollback_details": rollback_details
            }
            
        except Exception as e:
            print(f"❌ Rollback failed: {e}")
            return {
                "status": "FAILED",
                "message": f"Rollback failed: {str(e)}",
                "host": host
            }
    
    def _update_remediation_status(self, host: str, status: str):
        """Cập nhật trạng thái remediation log."""
        try:
            self.db.remediations.update_one(
                {"host": host},
                {"$set": {"rollback_status": status, "rollback_time": datetime.utcnow()}},
                upsert=True
            )
        except Exception as e:
            print(f"⚠️ Failed to update remediation status: {e}")
    
    def get_backups(self, host: str) -> list:
        """Lấy danh sách rule backups cho một Windows host (chỉ pre_remediation_backup)."""
        try:
            backups = list(self.db.backups.find(
                {
                    "host": host,
                    "type": "pre_remediation_backup"  # Chỉ lấy rule backups
                },
                sort=[("timestamp", -1)]
            ))
            for backup in backups:
                backup["_id"] = str(backup["_id"])
            return backups
        except Exception as e:
            print(f"❌ Failed to get backups: {e}")
            return []

rollback_manager = RollbackManager()
