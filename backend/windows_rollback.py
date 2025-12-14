"""Rollback module for Windows security hardening."""
import json
from datetime import datetime
from typing import Dict, Optional, List, Any
import winrm
from database import db
from windows_audit import winrm_connect
from utils import load_rules, RULES_DIR
import re
import os
import yaml

class RollbackManager:
    """Quản lý rollback cho Windows."""
    
    def __init__(self):
        self.db = db
    
    def create_backup(self, host: str, session: winrm.Session, rule_id: Optional[str] = None) -> str:
        """Tạo backup trạng thái hiện tại trước khi remediation - chỉ backup những gì rule sẽ sửa."""
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
                "rule_id": rule_id,  # Lưu rule_id để biết backup này dành cho rule nào
                "data": {}
            }
            
            # Xác định policies và registry keys cần backup dựa vào rule_id
            backup_scope = self._get_policies_to_backup_for_rule(rule_id)
            policies_to_backup = backup_scope.get("policies", [])
            registry_keys_to_backup = backup_scope.get("registry_keys", [])
            
            # Backup registry keys nếu có
            if registry_keys_to_backup:
                for reg_key in registry_keys_to_backup:
                    try:
                        reg_path = reg_key["path"]
                        value_name = reg_key["value_name"]
                        print(f"🔍 Backing up registry key: {reg_path}\\{value_name}...")
                        
                        reg_result = session.run_cmd(f'reg query "{reg_path}" /v {value_name}')
                        if reg_result.status_code == 0:
                            reg_output = reg_result.std_out.decode().strip()
                            # Parse registry value
                            # Format: "ValueName    REG_DWORD    0x0" or "ValueName    REG_SZ    value"
                            reg_key_backup = {
                                "path": reg_path,
                                "value_name": value_name,
                                "output": reg_output
                            }
                            
                            # Extract value type and data
                            if "REG_DWORD" in reg_output:
                                # Extract hex value (0x0, 0x1, etc.)
                                hex_match = re.search(r'0x([0-9a-fA-F]+)', reg_output)
                                if hex_match:
                                    reg_key_backup["value_type"] = "REG_DWORD"
                                    reg_key_backup["value_data"] = hex_match.group(0)
                            elif "REG_SZ" in reg_output:
                                # Extract string value
                                parts = reg_output.split("REG_SZ")
                                if len(parts) > 1:
                                    reg_key_backup["value_type"] = "REG_SZ"
                                    reg_key_backup["value_data"] = parts[1].strip()
                            
                            # Create backup key - cannot use backslash in f-string expression
                            reg_path_normalized = reg_path.replace('\\', '_').replace(':', '')
                            backup_key = f"registry_{reg_path_normalized}_{value_name}"
                            backup_data["data"][backup_key] = reg_key_backup
                            print(f"   ✓ Registry key backed up: {reg_path}\\{value_name}")
                        else:
                            # Key might not exist, backup that info
                            # Create backup key - cannot use backslash in f-string expression
                            reg_path_normalized = reg_path.replace('\\', '_').replace(':', '')
                            backup_key = f"registry_{reg_path_normalized}_{value_name}"
                            backup_data["data"][backup_key] = {
                                "path": reg_path,
                                "value_name": value_name,
                                "exists": False,
                                "note": "Registry key does not exist"
                            }
                            print(f"   ⚠️ Registry key does not exist: {reg_path}\\{value_name}")
                    except Exception as e:
                        print(f"   ⚠️ Error backing up registry key {reg_key.get('full_path', 'unknown')}: {e}")
            
            # 1. Backup Password Policy nếu rule sẽ sửa
            if "password" in policies_to_backup or not rule_id:
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
            
            # 2. Backup Remote Assistance nếu rule sẽ sửa
            if "remote_assistance" in policies_to_backup or not rule_id:
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
            
            # 3. Backup Administrator Account Status nếu rule sẽ sửa
            if "admin_account" in policies_to_backup or not rule_id:
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
            
            # 4. Backup Audit Policy nếu rule sẽ sửa
            if "audit_policy" in policies_to_backup or not rule_id:
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
                "rule_id": rule_id,
                "notes": f"Backup created before remediation for rule {rule_id} - Only policies that will be modified",
                "backup_scope": f"Rule-specific backup for {rule_id} - Only policies/configs that remediation will modify"
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
    
    def _extract_registry_keys_from_rule(self, rule_id: Optional[str]) -> List[Dict[str, str]]:
        """Extract registry keys từ rule YAML để backup."""
        registry_keys = []
        if not rule_id:
            return registry_keys
        
        try:
            # Load rule YAML
            rule = None
            windows_rules = load_rules("windows-10")  # Load Windows 10 rules
            for r in windows_rules:
                if isinstance(r, dict) and r.get("id") == rule_id:
                    rule = r
                    break
            
            if rule:
                # Extract registry keys từ check command
                check_cmd = rule.get("check", {}).get("winrm", "")
                if check_cmd and "reg query" in check_cmd:
                    # Parse reg query command để extract registry path và value name
                    # Format: reg query "HKLM\...\..." /v ValueName
                    import re
                    reg_pattern = r'reg query\s+"([^"]+)"\s+/v\s+(\S+)'
                    matches = re.findall(reg_pattern, check_cmd)
                    for reg_path, value_name in matches:
                        registry_keys.append({
                            "path": reg_path,
                            "value_name": value_name,
                            "full_path": f"{reg_path}\\{value_name}"
                        })
        except Exception as e:
            print(f"   ⚠️ Failed to extract registry keys from rule: {e}")
        
        return registry_keys
    
    def _get_policies_to_backup_for_rule(self, rule_id: Optional[str]) -> Dict[str, Any]:
        """Xác định các policies và registry keys cần backup dựa vào rule_id."""
        if not rule_id:
            # Fallback: backup tất cả nếu không có rule_id
            return {
                "policies": ["password", "remote_assistance", "admin_account", "audit_policy"],
                "registry_keys": []
            }
        
        policies = []
        registry_keys = []
        
        # Extract registry keys từ rule YAML
        registry_keys = self._extract_registry_keys_from_rule(rule_id)
        
        # Rule về password policy
        if any(x in rule_id.lower() for x in ['password', 'account', 'lockout', '1.1.', '1.2.']):
            policies.append("password")
        
        # Rule về remote access
        if any(x in rule_id.lower() for x in ['remote', 'assistance', 'rdp']):
            policies.append("remote_assistance")
        
        # Rule về admin account
        if any(x in rule_id.lower() for x in ['admin', 'administrator']):
            policies.append("admin_account")
        
        # Rule về audit/logging
        if any(x in rule_id.lower() for x in ['audit', 'logging', 'logon', '17.']):
            policies.append("audit_policy")
        
        # Rule về network security (2.3.x) - thường sửa registry
        if '2.3.' in rule_id:
            # Nếu chưa có registry keys từ YAML, thử detect từ rule ID
            if not registry_keys:
                # Common registry paths for 2.3.x rules
                if '2.3.10.1' in rule_id or 'anonymous' in rule_id.lower():
                    registry_keys.append({
                        "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                        "value_name": "TurnOffAnonymousBlock",
                        "full_path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\TurnOffAnonymousBlock"
                    })
                elif '2.3.11.7' in rule_id or 'lan manager' in rule_id.lower():
                    registry_keys.append({
                        "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                        "value_name": "LmCompatibilityLevel",
                        "full_path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel"
                    })
        
        # Nếu không tìm thấy, backup password policy (phổ biến nhất)
        if not policies and not registry_keys:
            policies.append("password")
        
        return {
            "policies": policies,
            "registry_keys": registry_keys
        }
    
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
            
            # 5. Khôi phục Registry Keys nếu có
            for key, reg_data in backup["data"].items():
                if key.startswith("registry_") and isinstance(reg_data, dict):
                    try:
                        reg_path = reg_data.get("path")
                        value_name = reg_data.get("value_name")
                        value_type = reg_data.get("value_type", "REG_DWORD")
                        value_data = reg_data.get("value_data")
                        exists = reg_data.get("exists", True)
                        
                        if not exists:
                            # Registry key didn't exist, delete it if it exists now
                            print(f"🔄 Registry key {reg_path}\\{value_name} did not exist originally, skipping restore")
                            rollback_details[f"registry_{key}"] = {
                                "status": "SKIPPED",
                                "message": "Registry key did not exist originally"
                            }
                            continue
                        
                        if not reg_path or not value_name or not value_data:
                            continue
                        
                        print(f"🔄 Restoring registry key: {reg_path}\\{value_name} = {value_data}")
                        
                        # Restore registry value
                        if value_type == "REG_DWORD":
                            # Convert hex to decimal for reg add command
                            if value_data.startswith("0x"):
                                decimal_value = int(value_data, 16)
                            else:
                                decimal_value = int(value_data)
                            cmd = f'reg add "{reg_path}" /v {value_name} /t {value_type} /d {decimal_value} /f'
                        else:
                            # REG_SZ or other types
                            cmd = f'reg add "{reg_path}" /v {value_name} /t {value_type} /d "{value_data}" /f'
                        
                        result = session.run_cmd(cmd)
                        
                        # Verify restoration
                        verify_result = session.run_cmd(f'reg query "{reg_path}" /v {value_name}')
                        verified = False
                        if verify_result.status_code == 0:
                            verify_output = verify_result.std_out.decode().strip()
                            if value_data in verify_output or str(decimal_value) in verify_output:
                                verified = True
                        
                        rollback_details[f"registry_{key}"] = {
                            "status": "RESTORED" if verified else "PARTIAL",
                            "command": cmd,
                            "result": result.std_out.decode(),
                            "exit_code": result.status_code,
                            "verified": verified,
                            "message": f"Registry key restored: {reg_path}\\{value_name} = {value_data}"
                        }
                        
                        if verified:
                            print(f"   ✓ Registry key restored: {reg_path}\\{value_name} = {value_data}")
                        else:
                            print(f"   ⚠️ Registry key restore verification failed: {reg_path}\\{value_name}")
                    except Exception as e:
                        print(f"   ⚠️ Error restoring registry key {key}: {e}")
                        rollback_details[f"registry_{key}"] = {
                            "status": "ERROR",
                            "error": str(e),
                            "message": f"Error restoring registry key: {e}"
                        }
            
            # Lưu rollback log
            rollback_log = {
                "host": host,
                "backup_id": backup["backup_id"],
                "timestamp": datetime.utcnow(),
                "type": "rollback_executed",
                "os_type": "windows",
                "rollback_details": rollback_details,
                "status": "SUCCESS" if all(d.get("status") in ["RESTORED", "SKIPPED"] for d in rollback_details.values() if isinstance(d, dict)) else "PARTIAL"
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
                    "os_type": "windows",
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
