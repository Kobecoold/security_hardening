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
    """Quản lý rollback cho Windows - Rule-specific như Ubuntu."""
    
    def __init__(self):
        self.db = db
    
    # Windows Rule Mapping
    WINDOWS_RULE_MAPPING = {
        # 1. Account Policies
        "winrm-cis-windows10-1.1.1": {
            "type": "net_accounts",
            "settings": ["/uniquepw"],
            "backup_command": 'net accounts | findstr "Length of password history maintained"',
            "restore_command": "net accounts /uniquepw:{value}",
            "registry_backup": False
        },
        "winrm-cis-windows10-1.1.2": {
            "type": "net_accounts",
            "settings": ["/maxpwage"],
            "backup_command": 'net accounts | findstr "Maximum password age"',
            "restore_command": "net accounts /maxpwage:{value}",
            "registry_backup": False
        },
        "winrm-cis-windows10-1.1.4": {
            "type": "net_accounts",
            "settings": ["/minpwlen"],
            "backup_command": 'net accounts | findstr "Minimum password length"',
            "restore_command": "net accounts /minpwlen:{value}",
            "registry_backup": False
        },
        "winrm-cis-windows10-1.1.5": {
            "type": "secedit",
            "settings": ["PasswordComplexity"],
            "backup_command": 'secedit /export /cfg %temp%\\sec.cfg && type "%temp%\\sec.cfg" | findstr "PasswordComplexity"',
            "restore_command_template": "echo [Unicode]\\nUnicode=yes\\n[Version]\\nsignature=\"$CHICAGO$\"\\nRevision=1\\n[System Access]\\nPasswordComplexity = {value} > %temp%\\pass_complex.inf && secedit /configure /db %windir%\\security\\local.sdb /cfg %temp%\\pass_complex.inf /areas SECURITYPOLICY",
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "PasswordComplexity"
        },
        "winrm-cis-windows10-1.1.7": {
            "type": "secedit",
            "settings": ["ClearTextPassword"],
            "backup_command": 'secedit /export /cfg %temp%\\sec.cfg && type "%temp%\\sec.cfg" | findstr "ClearTextPassword"',
            "restore_command_template": "echo [Unicode]\\nUnicode=yes\\n[Version]\\nsignature=\"$CHICAGO$\"\\nRevision=1\\n[System Access]\\nClearTextPassword = {value} > %temp%\\clear_pass.inf && secedit /configure /db %windir%\\security\\local.sdb /cfg %temp%\\clear_pass.inf /areas SECURITYPOLICY",
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "ClearTextPassword"
        },
        
        # 2. Security Options
        "winrm-cis-windows10-2.3.1.2": {
            "type": "net_user",
            "settings": ["guest"],
            "backup_command": 'net user guest | findstr "Account active"',
            "restore_command": "net user guest /active:{value}",
            "registry_backup": False
        },
        "winrm-cis-windows10-2.3.1.3": {
            "type": "registry",
            "settings": ["LimitBlankPasswordUse"],
            "backup_command": r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse',
            "restore_command": r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "LimitBlankPasswordUse"
        },
        "winrm-cis-windows10-2.3.2.1": {
            "type": "registry",
            "settings": ["SCENoApplyLegacyAuditPolicy"],
            "backup_command": r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy',
            "restore_command": r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "SCENoApplyLegacyAuditPolicy"
        },
        "winrm-cis-windows10-2.3.7.1": {
            "type": "registry",
            "settings": ["DisableCAD"],
            "backup_command": r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD',
            "restore_command": r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "registry_value": "DisableCAD"
        },
        "winrm-cis-windows10-2.3.7.2": {
            "type": "registry",
            "settings": ["DontDisplayLastUserName"],
            "backup_command": r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName',
            "restore_command": r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "registry_value": "DontDisplayLastUserName"
        },
        "winrm-cis-windows10-2.3.10.1": {
            "type": "registry",
            "settings": ["TurnOffAnonymousBlock"],
            "backup_command": r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v TurnOffAnonymousBlock',
            "restore_command": r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v TurnOffAnonymousBlock /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "TurnOffAnonymousBlock"
        },
        "winrm-cis-windows10-2.3.10.2": {
            "type": "registry",
            "settings": ["RestrictAnonymousSAM"],
            "backup_command": r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM',
            "restore_command": r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "RestrictAnonymousSAM"
        },
        "winrm-cis-windows10-2.3.11.5": {
            "type": "registry",
            "settings": ["NoLMHash"],
            "backup_command": r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash',
            "restore_command": r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "NoLMHash"
        },
        "winrm-cis-windows10-2.3.11.7": {
            "type": "registry",
            "settings": ["LmCompatibilityLevel"],
            "backup_command": r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel',
            "restore_command": r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "registry_value": "LmCompatibilityLevel"
        },
        
        # 3. Firewall Rules
        "winrm-cis-windows10-9.1.1": {
            "type": "netsh",
            "settings": ["domainprofile state"],
            "backup_command": 'netsh advfirewall show domainprofile state | findstr "State"',
            "restore_command": "netsh advfirewall set domainprofile state {value}",
            "registry_backup": False
        },
        "winrm-cis-windows10-9.1.2": {
            "type": "netsh",
            "settings": ["domainprofile firewallpolicy"],
            "backup_command": 'netsh advfirewall show domainprofile firewallpolicy | findstr "Firewall Policy"',
            "restore_command": "netsh advfirewall set domainprofile firewallpolicy {value},allowoutbound",
            "registry_backup": False
        },
        "winrm-cis-windows10-9.1.3": {
            "type": "netsh",
            "settings": ["domainprofile settings"],
            "backup_command": 'netsh advfirewall show domainprofile settings | findstr "Inbound user notification"',
            "restore_command": "netsh advfirewall set domainprofile settings inboundusernotification {value}",
            "registry_backup": False
        },
        
        # 4. Audit Policies
        "winrm-cis-windows10-17.1.1": {
            "type": "auditpol",
            "settings": ["Credential Validation"],
            "backup_command": 'auditpol /get /subcategory:"Credential Validation" | findstr "Credential Validation"',
            "restore_command": 'auditpol /set /subcategory:"Credential Validation" /success:{success} /failure:{failure}',
            "registry_backup": False
        },
        "winrm-cis-windows10-17.5.4": {
            "type": "auditpol",
            "settings": ["Logon"],
            "backup_command": 'auditpol /get /subcategory:"Logon" | findstr "Logon"',
            "restore_command": 'auditpol /set /subcategory:"Logon" /success:{success} /failure:{failure}',
            "registry_backup": False
        },
        "winrm-cis-windows10-17.9.1": {
            "type": "auditpol",
            "settings": ["IPsec Driver"],
            "backup_command": 'auditpol /get /subcategory:"IPsec Driver" | findstr "IPsec Driver"',
            "restore_command": 'auditpol /set /subcategory:"IPsec Driver" /success:{success} /failure:{failure}',
            "registry_backup": False
        },
        
        # 5. Network Security
        "winrm-cis-windows10-18.9.3.1": {
            "type": "registry",
            "settings": ["ProcessCreationIncludeCmdLine_Enabled"],
            "backup_command": r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled',
            "restore_command": r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d {value} /f',
            "registry_backup": True,
            "registry_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "registry_value": "ProcessCreationIncludeCmdLine_Enabled"
        }
    }
    
    def _get_settings_to_backup_for_rule(self, rule_id: Optional[str]) -> Dict:
        """Xác định settings cần backup dựa vào rule_id (giống Linux)."""
        if not rule_id:
            # Fallback: backup các setting cơ bản nếu không có rule_id
            return {
                "type": "fallback",
                "settings": ["net_accounts", "guest_account", "audit_basic"],
                "description": "Fallback backup for unknown rule"
            }
        
        if rule_id in self.WINDOWS_RULE_MAPPING:
            rule_info = self.WINDOWS_RULE_MAPPING[rule_id].copy()
            rule_info["rule_id"] = rule_id
            return rule_info
        
        # Nếu không tìm thấy trong mapping, dựa vào tên rule để xác định loại
        rule_lower = rule_id.lower()
        
        if "password" in rule_lower or "1.1." in rule_id:
            return {
                "type": "net_accounts",
                "rule_id": rule_id,
                "settings": ["all_password_policies"],
                "description": "Password policy backup"
            }
        elif "guest" in rule_lower or "2.3.1.2" in rule_id:
            return {
                "type": "net_user",
                "rule_id": rule_id,
                "settings": ["guest"],
                "description": "Guest account backup"
            }
        elif "audit" in rule_lower or "17." in rule_id:
            return {
                "type": "auditpol",
                "rule_id": rule_id,
                "settings": ["all_audit_policies"],
                "description": "Audit policy backup"
            }
        elif "firewall" in rule_lower or "9." in rule_id:
            return {
                "type": "netsh",
                "rule_id": rule_id,
                "settings": ["domainprofile"],
                "description": "Firewall settings backup"
            }
        else:
            # Thử extract registry keys từ rule YAML file
            try:
                rules = load_rules()
                rule_data = None
                for r in rules:
                    if r.get("id") == rule_id:
                        rule_data = r
                        break
                
                if rule_data:
                    check_cmd = rule_data.get("check", {}).get("winrm", "")
                    # Parse registry query command: reg query "HKLM\...\Path" /v ValueName
                    reg_match = re.search(r'reg query\s+"([^"]+)"\s+/v\s+(\S+)', check_cmd)
                    if reg_match:
                        reg_path = reg_match.group(1)
                        value_name = reg_match.group(2)
                        return {
                            "type": "registry",
                            "rule_id": rule_id,
                            "registry_path": reg_path,
                            "registry_value": value_name,
                            "value_name": value_name,  # Alias for compatibility
                            "description": f"Registry backup for {rule_id}"
                        }
            except Exception as e:
                print(f"   ⚠️ Failed to extract registry from rule YAML: {e}")
            
            # Default: backup registry keys phổ biến
            return {
                "type": "registry_fallback",
                "rule_id": rule_id,
                "settings": ["common_registry_keys"],
                "description": "Common registry backup"
            }
    
    def create_backup(self, host: str, session: winrm.Session, rule_id: Optional[str] = None) -> Optional[str]:
        """Tạo backup chỉ những settings mà rule sẽ sửa (giống Linux)."""
        try:
            print(f"🛡️ Starting rule-specific backup for Windows host: {host}, rule: {rule_id}")
            
            # Kiểm tra connection trước
            test_result = session.run_cmd('echo Backup Test')
            if test_result.status_code != 0:
                print(f"⚠️ Connection test failed: {test_result.std_err.decode()}")
            
            # Xác định settings cần backup
            backup_plan = self._get_settings_to_backup_for_rule(rule_id)
            backup_type = backup_plan.get("type", "unknown")
            rule_id = backup_plan.get("rule_id", rule_id)
            
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "pre_remediation_backup",
                "os_type": "windows",
                "backup_id": f"win_backup_{int(datetime.utcnow().timestamp())}_{rule_id}",
                "rule_id": rule_id,
                "backup_type": backup_type,
                "data": {}
            }
            
            # Backup theo từng loại setting
            print(f"📋 Backup plan: {backup_type} for rule {rule_id}")
            
            try:
                if backup_type == "net_accounts":
                    self._backup_net_accounts(session, backup_data)
                elif backup_type == "net_user":
                    self._backup_net_user_guest(session, backup_data)
                elif backup_type == "secedit":
                    self._backup_secedit_policy(session, backup_data, backup_plan)
                elif backup_type == "registry":
                    self._backup_registry_key(session, backup_data, backup_plan)
                elif backup_type == "netsh":
                    self._backup_netsh_firewall(session, backup_data, backup_plan)
                elif backup_type == "auditpol":
                    self._backup_auditpol_policy(session, backup_data, backup_plan)
                elif backup_type == "fallback":
                    # Fallback: backup cơ bản
                    self._backup_fallback_settings(session, backup_data)
                else:
                    print(f"⚠️ Unknown backup type: {backup_type}, using fallback")
                    self._backup_fallback_settings(session, backup_data)
                    
            except Exception as backup_error:
                print(f"⚠️ Error during specific backup: {backup_error}")
                # Vẫn tiếp tục với fallback backup
                self._backup_fallback_settings(session, backup_data)
            
            # Thêm backup info
            backup_data["data"]["backup_info"] = {
                "backup_time": str(datetime.utcnow()),
                "host": host,
                "rule_id": rule_id,
                "backup_type": backup_type,
                "description": backup_plan.get("description", "Rule-specific backup"),
                "notes": f"Rule-specific backup for {rule_id} - Only settings that will be modified",
                "scope": f"Windows settings backup for rule: {rule_id}"
            }
            
            # Save to MongoDB
            backup_id = self._save_backup(backup_data)
            print(f"✅ Rule-specific backup created for {host}: {backup_id}")
            return backup_id
            
        except Exception as e:
            print(f"❌ Rule-specific backup creation failed: {e}")
            import traceback
            traceback.print_exc()
            # Không raise exception để remediation vẫn chạy được
            return None
    
    def create_backup_for_rules(self, host: str, session: winrm.Session, rule_ids: Optional[List[str]] = None) -> Optional[str]:
        """Tạo backup chung cho nhiều rules - merge tất cả settings cần backup."""
        if not rule_ids or len(rule_ids) == 0:
            return None
        
        try:
            print(f"🛡️ Starting batch backup for Windows host: {host} with {len(rule_ids)} rules")
            
            # Collect tất cả backup plans từ tất cả rules
            all_backup_plans = []
            all_registry_keys = set()
            all_policies = set()
            
            for rule_id in rule_ids:
                if rule_id:
                    backup_plan = self._get_settings_to_backup_for_rule(rule_id)
                    all_backup_plans.append(backup_plan)
                    
                    # Collect registry keys và policies
                    registry_extracted = False
                    if backup_plan.get("type") == "registry":
                        reg_path = backup_plan.get("registry_path")
                        value_name = backup_plan.get("registry_value") or backup_plan.get("value_name")
                        if reg_path and value_name and value_name != "None" and value_name.strip() != "":
                            all_registry_keys.add((reg_path, value_name))
                            registry_extracted = True
                    
                    # Nếu không có registry keys hợp lệ, thử extract từ rule YAML
                    if not registry_extracted:
                        try:
                            rules = load_rules()
                            rule_data = None
                            for r in rules:
                                if r.get("id") == rule_id:
                                    rule_data = r
                                    break
                            
                            if rule_data:
                                check_cmd = rule_data.get("check", {}).get("winrm", "")
                                # Parse registry query command: reg query "HKLM\...\Path" /v ValueName
                                reg_match = re.search(r'reg query\s+"([^"]+)"\s+/v\s+(\S+)', check_cmd)
                                if reg_match:
                                    reg_path = reg_match.group(1)
                                    value_name = reg_match.group(2)
                                    # Validate value_name trước khi add
                                    if value_name and value_name != "None" and value_name.strip() != "":
                                        all_registry_keys.add((reg_path, value_name))
                                        print(f"   📋 Rule {rule_id}: extracted registry {reg_path}\\{value_name} from YAML")
                                    else:
                                        print(f"   ⚠️ Rule {rule_id}: extracted invalid value_name '{value_name}' from YAML, skipping")
                                else:
                                    print(f"   ⚠️ Rule {rule_id}: no registry pattern found in check command: {check_cmd[:100]}")
                        except Exception as e:
                            print(f"   ⚠️ Failed to extract registry from rule YAML for {rule_id}: {e}")
                    
                    policies = backup_plan.get("policies", [])
                    if policies:
                        all_policies.update(policies)
                    
                    print(f"   📋 Rule {rule_id}: type={backup_plan.get('type')}")
            
            print(f"✅ Total unique settings to backup: {len(all_registry_keys)} registry keys, {len(all_policies)} policies")
            
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "pre_remediation_backup",
                "os_type": "windows",
                "backup_id": f"win_backup_{int(datetime.utcnow().timestamp())}",
                "rule_ids": rule_ids,  # Lưu danh sách rules
                "rule_id": None,  # Không có rule_id đơn lẻ
                "backup_type": "batch",
                "data": {}
            }
            
            try:
                # Backup registry keys - lưu dạng dict để rollback dễ parse
                for reg_path, value_name in all_registry_keys:
                    # Validate value_name - skip nếu None hoặc empty
                    if not value_name or value_name == "None" or value_name.strip() == "":
                        print(f"   ⚠️ Skipping registry backup: invalid value_name '{value_name}' for path {reg_path}")
                        continue
                    
                    try:
                        print(f"🔍 Backing up registry: {reg_path}\\{value_name}...")
                        cmd = f'reg query "{reg_path}" /v "{value_name}" 2>nul'
                        result = session.run_cmd(cmd)
                        if result.status_code == 0:
                            output = result.std_out.decode('utf-8', errors='ignore').strip()
                            # Parse registry value
                            lines = output.split('\n')
                            for line in lines:
                                if value_name in line and ('REG_DWORD' in line or 'REG_SZ' in line or 'REG_MULTI_SZ' in line):
                                    # Parse line: "    value_name    REG_DWORD    0x1"
                                    parts = line.strip().split()
                                    if len(parts) >= 3:
                                        reg_type = parts[1]  # REG_DWORD, REG_SZ, etc.
                                        reg_value = parts[2]  # 0x1, value string, etc.
                                        
                                        # Normalize path for backup key (sanitize value_name để tránh ký tự đặc biệt)
                                        reg_path_normalized = reg_path.replace('\\', '_').replace(':', '_')
                                        value_name_safe = value_name.replace('\\', '_').replace('/', '_').replace(':', '_')
                                        backup_key = f"registry_{reg_path_normalized}_{value_name_safe}"
                                        
                                        # Lưu dạng dict để rollback dễ parse
                                        backup_data["data"][backup_key] = {
                                            "path": reg_path,
                                            "value_name": value_name,
                                            "value_type": reg_type,
                                            "value_data": reg_value,
                                            "exists": True
                                        }
                                        print(f"   ✓ Registry backed up: {reg_path}\\{value_name} = {reg_value} ({reg_type})")
                                        break
                        else:
                            # Registry key không tồn tại - vẫn backup để biết trạng thái
                            reg_path_normalized = reg_path.replace('\\', '_').replace(':', '_')
                            value_name_safe = value_name.replace('\\', '_').replace('/', '_').replace(':', '_')
                            backup_key = f"registry_{reg_path_normalized}_{value_name_safe}"
                            backup_data["data"][backup_key] = {
                                "path": reg_path,
                                "value_name": value_name,
                                "exists": False
                            }
                            print(f"   ⚠️ Registry key does not exist: {reg_path}\\{value_name}")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup registry {reg_path}\\{value_name}: {e}")
                
                # Backup policies
                for policy in all_policies:
                    try:
                        print(f"🔍 Backing up policy: {policy}...")
                        if policy == "password":
                            self._backup_net_accounts(session, backup_data)
                        elif policy == "guest":
                            self._backup_net_user_guest(session, backup_data)
                        # Có thể thêm các policies khác
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup policy {policy}: {e}")
                
                # Backup secedit, netsh, auditpol nếu có rules liên quan
                has_secedit = any(plan.get("type") == "secedit" for plan in all_backup_plans)
                has_netsh = any(plan.get("type") == "netsh" for plan in all_backup_plans)
                has_auditpol = any(plan.get("type") == "auditpol" for plan in all_backup_plans)
                
                if has_secedit:
                    try:
                        print("🔍 Backing up secedit policies...")
                        # Backup secedit export
                        cmd = 'secedit /export /cfg C:\\temp_secedit_backup.inf 2>nul'
                        result = session.run_cmd(cmd)
                        if result.status_code == 0:
                            # Read the exported file
                            read_cmd = 'type C:\\temp_secedit_backup.inf 2>nul'
                            read_result = session.run_cmd(read_cmd)
                            if read_result.status_code == 0:
                                backup_data["data"]["secedit_export"] = read_result.std_out.decode('utf-8', errors='ignore')[:100000]
                                print(f"   ✓ Secedit policies backed up")
                            # Cleanup
                            session.run_cmd('del C:\\temp_secedit_backup.inf 2>nul')
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup secedit: {e}")
                
                if has_netsh:
                    try:
                        print("🔍 Backing up firewall rules...")
                        cmd = 'netsh advfirewall firewall show rule name=all dir=in type=static 2>nul'
                        result = session.run_cmd(cmd)
                        if result.status_code == 0:
                            backup_data["data"]["firewall_rules_in"] = result.std_out.decode('utf-8', errors='ignore')[:100000]
                            print(f"   ✓ Firewall rules (inbound) backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup firewall: {e}")
                
                if has_auditpol:
                    try:
                        print("🔍 Backing up audit policies...")
                        cmd = 'auditpol /get /category:* 2>nul'
                        result = session.run_cmd(cmd)
                        if result.status_code == 0:
                            backup_data["data"]["auditpol"] = result.std_out.decode('utf-8', errors='ignore')[:100000]
                            print(f"   ✓ Audit policies backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup auditpol: {e}")
                
                # Backup info
                rule_count = len(rule_ids)
                if rule_count == 1:
                    backup_scope_msg = f"Backup for 1 rule: {rule_ids[0]}"
                    notes_msg = f"Backup created before remediation for 1 rule - Only settings that will be modified"
                    desc_msg = f"Backup for 1 rule"
                else:
                    backup_scope_msg = f"Backup for {rule_count} rules: {', '.join(rule_ids[:5])}{'...' if rule_count > 5 else ''}"
                    notes_msg = f"Backup created before remediation for {rule_count} rules - Only settings that will be modified"
                    desc_msg = f"Backup for {rule_count} rules"
                
                backup_data["data"]["backup_info"] = {
                    "backup_time": str(datetime.utcnow()),
                    "host": host,
                    "rule_ids": rule_ids,
                    "rule_count": rule_count,
                    "backup_type": "batch" if rule_count > 1 else "single",
                    "description": desc_msg,
                    "notes": notes_msg,
                    "scope": backup_scope_msg
                }
                
            except Exception as backup_error:
                print(f"⚠️ Error during batch backup: {backup_error}")
                # Vẫn tiếp tục với fallback backup
                self._backup_fallback_settings(session, backup_data)
            
            # Save to MongoDB
            backup_id = self._save_backup(backup_data)
            rule_count = len(rule_ids)
            if rule_count == 1:
                print(f"✅ Backup created for {host}: {backup_id} (covers 1 rule: {rule_ids[0]})")
            else:
                print(f"✅ Backup created for {host}: {backup_id} (covers {rule_count} rules)")
            return backup_id
            
        except Exception as e:
            print(f"❌ Batch backup creation failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _backup_net_accounts(self, session: winrm.Session, backup_data: Dict):
        """Backup net accounts settings."""
        try:
            print("🔍 Backing up net accounts settings...")
            result = session.run_cmd('net accounts')
            if result.status_code == 0:
                output = result.std_out.decode().strip()
                backup_data["data"]["net_accounts"] = output
                print(f"   ✓ Net accounts backed up ({len(output)} bytes)")
                
                # Parse specific values for easier restoration
                parsed = {}
                for line in output.split('\n'):
                    if 'Length of password history maintained' in line:
                        match = re.search(r':\s+(\d+)', line)
                        if match:
                            parsed['PasswordHistorySize'] = match.group(1)
                    elif 'Maximum password age' in line:
                        match = re.search(r':\s+(\d+)', line)
                        if match:
                            parsed['MaximumPasswordAge'] = match.group(1)
                    elif 'Minimum password length' in line:
                        match = re.search(r':\s+(\d+)', line)
                        if match:
                            parsed['MinimumPasswordLength'] = match.group(1)
                
                if parsed:
                    backup_data["data"]["parsed_net_accounts"] = parsed
                    print(f"   ✓ Parsed {len(parsed)} net account values")
                    
        except Exception as e:
            print(f"   ⚠️ Failed to backup net accounts: {e}")
    
    def _backup_registry_key(self, session: winrm.Session, backup_data: Dict, backup_plan: Dict):
        """Backup một registry key cụ thể."""
        try:
            registry_path = backup_plan.get("registry_path")
            value_name = backup_plan.get("registry_value")
            
            if not registry_path or not value_name:
                print(f"   ⚠️ No registry path/value specified in backup plan")
                return
                
            print(f"🔍 Backing up registry: {registry_path}\\{value_name}")
            
            result = session.run_cmd(f'reg query "{registry_path}" /v {value_name}')
            
            if result.status_code == 0:
                output = result.std_out.decode().strip()
                lines = output.split('\n')
                
                for line in lines:
                    if value_name in line:
                        # Parse: REG_DWORD    0x1
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            reg_type = parts[1]
                            reg_value = parts[2]
                            
                            # Create backup key - cannot use backslash in f-string expression
                            registry_path_normalized = registry_path.replace('\\', '_').replace(':', '_')
                            reg_key = f"registry_{registry_path_normalized}_{value_name}"
                            backup_data["data"][reg_key] = {
                                "path": registry_path,
                                "value_name": value_name,
                                "value": reg_value,
                                "type": reg_type,
                                "status": "EXISTS"
                            }
                            print(f"   ✓ Registry backed up: {value_name} = {reg_value} ({reg_type})")
                            break
            else:
                # Key không tồn tại
                # Create backup key - cannot use backslash in f-string expression
                registry_path_normalized = registry_path.replace('\\', '_').replace(':', '_')
                reg_key = f"registry_{registry_path_normalized}_{value_name}"
                backup_data["data"][reg_key] = {
                    "path": registry_path,
                    "value_name": value_name,
                    "status": "KEY_NOT_EXIST"
                }
                print(f"   ⚠️ Registry key does not exist: {value_name}")
                
        except Exception as e:
            print(f"   ⚠️ Failed to backup registry: {e}")
    
    def _backup_secedit_policy(self, session: winrm.Session, backup_data: Dict, backup_plan: Dict):
        """Backup secedit security policy."""
        try:
            print("🔍 Backing up security policy via secedit...")
            
            # Tạo temp file name
            temp_file = f"sec_backup_{int(datetime.utcnow().timestamp())}.inf"
            temp_path = f"C:\\Windows\\Temp\\{temp_file}"
            
            # Export security policy
            result = session.run_cmd(f'secedit /export /cfg {temp_path} /quiet')
            
            if result.status_code == 0:
                # Read the exported file
                read_result = session.run_cmd(f'type {temp_path}')
                if read_result.status_code == 0:
                    policy_content = read_result.std_out.decode()
                    backup_data["data"]["secedit_policy"] = policy_content
                    print(f"   ✓ Security policy backed up ({len(policy_content)} bytes)")
                    
                    # Parse specific values
                    settings = backup_plan.get("settings", [])
                    parsed = {}
                    for setting in settings:
                        if setting in policy_content:
                            # Extract value
                            lines = policy_content.split('\n')
                            for line in lines:
                                if f"{setting} =" in line:
                                    match = re.search(r'=\s*(\d+)', line)
                                    if match:
                                        parsed[setting] = match.group(1)
                                        break
                    
                    if parsed:
                        backup_data["data"]["parsed_secedit"] = parsed
                        print(f"   ✓ Parsed {len(parsed)} security policy values")
                
                # Clean up temp file
                session.run_cmd(f'del {temp_path}')
                
        except Exception as e:
            print(f"   ⚠️ Failed to backup security policy: {e}")
    
    def _backup_auditpol_policy(self, session: winrm.Session, backup_data: Dict, backup_plan: Dict):
        """Backup audit policy settings."""
        try:
            settings = backup_plan.get("settings", [])
            print(f"🔍 Backing up audit policy: {settings}")
            
            for setting in settings:
                result = session.run_cmd(f'auditpol /get /subcategory:"{setting}"')
                if result.status_code == 0:
                    output = result.std_out.decode().strip()
                    backup_data["data"][f"auditpol_{setting.replace(' ', '_')}"] = output
                    print(f"   ✓ Audit policy backed up for: {setting}")
                    
                    # Parse success/failure settings
                    success_setting = "No Auditing"
                    failure_setting = "No Auditing"
                    
                    lines = output.split('\n')
                    for line in lines:
                        if "Success" in line and "enable" in line.lower():
                            success_setting = "enable"
                        elif "Failure" in line and "enable" in line.lower():
                            failure_setting = "enable"
                        elif "Success" in line and "disable" in line.lower():
                            success_setting = "disable"
                        elif "Failure" in line and "disable" in line.lower():
                            failure_setting = "disable"
                    
                    backup_data["data"][f"auditpol_parsed_{setting.replace(' ', '_')}"] = {
                        "subcategory": setting,
                        "success": success_setting,
                        "failure": failure_setting
                    }
                    
        except Exception as e:
            print(f"   ⚠️ Failed to backup audit policy: {e}")
    
    def _backup_fallback_settings(self, session: winrm.Session, backup_data: Dict):
        """Fallback backup khi không xác định được loại cụ thể."""
        try:
            print("🔍 Performing fallback backup...")
            
            # Backup net accounts (cơ bản)
            self._backup_net_accounts(session, backup_data)
            
            # Backup guest account
            self._backup_net_user_guest(session, backup_data)
            
            print("   ✓ Fallback backup completed")
            
        except Exception as e:
            print(f"   ⚠️ Fallback backup failed: {e}")
    
    def _backup_net_user_guest(self, session: winrm.Session, backup_data: Dict):
        """Backup guest account status."""
        try:
            print("🔍 Backing up guest account status...")
            result = session.run_cmd('net user guest')
            if result.status_code == 0:
                output = result.std_out.decode().strip()
                backup_data["data"]["guest_account"] = output
                
                # Parse account active status
                if "Account active" in output and "Yes" in output:
                    backup_data["data"]["guest_account_active"] = True
                else:
                    backup_data["data"]["guest_account_active"] = False
                    
                print(f"   ✓ Guest account backed up")
                
        except Exception as e:
            print(f"   ⚠️ Failed to backup guest account: {e}")
    
    def _backup_netsh_firewall(self, session: winrm.Session, backup_data: Dict, backup_plan: Dict):
        """Backup firewall settings."""
        try:
            settings = backup_plan.get("settings", [])
            print(f"🔍 Backing up firewall settings: {settings}")
            
            for setting in settings:
                result = session.run_cmd(f'netsh advfirewall show domainprofile {setting}')
                if result.status_code == 0:
                    output = result.std_out.decode().strip()
                    backup_data["data"][f"netsh_{setting.replace(' ', '_')}"] = output
                    print(f"   ✓ Firewall setting backed up: {setting}")
                    
        except Exception as e:
            print(f"   ⚠️ Failed to backup firewall settings: {e}")
    
    def _save_backup(self, backup_data: Dict) -> str:
        """Lưu backup vào MongoDB."""
        try:
            result = self.db.backups.insert_one(backup_data)
            return str(result.inserted_id)
        except Exception as e:
            print(f"❌ Failed to save backup to MongoDB: {e}")
            return f"backup_error_{int(datetime.utcnow().timestamp())}"
    
    def execute_rollback(self, host: str, session: winrm.Session, backup_id: Optional[str] = None, 
                         rule_id: Optional[str] = None) -> Dict:
        """Rollback chỉ những settings đã backup cho rule cụ thể (giống Linux)."""
        try:
            # Tìm backup - hỗ trợ cả single rule và batch backups
            if backup_id:
                backup = self.db.backups.find_one({"backup_id": backup_id, "host": host})
            elif rule_id:
                # Tìm backup gần nhất cho rule này - hỗ trợ cả single và batch backups
                query = {
                    "host": host,
                    "type": "pre_remediation_backup",
                    "os_type": "windows",
                    "$or": [
                        {"rule_id": rule_id},  # Single rule backup
                        {"rule_ids": rule_id}  # Batch backup chứa rule này
                    ]
                }
                backup = self.db.backups.find_one(query, sort=[("timestamp", -1)])
            else:
                # Tìm backup gần nhất (bất kỳ rule nào)
                backup = self.db.backups.find_one(
                    {
                        "host": host, 
                        "type": "pre_remediation_backup",
                        "os_type": "windows"
                    },
                    sort=[("timestamp", -1)]
                )
            
            if not backup:
                error_msg = f"No backup found for Windows host {host}"
                if rule_id:
                    error_msg += f" with rule {rule_id}"
                return {
                    "status": "SKIPPED",
                    "message": error_msg,
                    "host": host,
                    "rule_id": rule_id,
                    "error": "BACKUP_NOT_FOUND"
                }
            
            # Xác định loại backup (single rule hoặc batch)
            backup_rule_id = backup.get("rule_id")
            backup_rule_ids = backup.get("rule_ids")
            is_batch_backup = backup_rule_ids is not None and len(backup_rule_ids) > 0
            
            if is_batch_backup:
                print(f"🔄 Starting batch rollback for {host}, rules: {', '.join(backup_rule_ids[:3])}{'...' if len(backup_rule_ids) > 3 else ''}")
                print(f"   Backup ID: {backup.get('backup_id')}")
                print(f"   Backup type: {backup.get('backup_type', 'batch')}")
                print(f"   Total rules in backup: {len(backup_rule_ids)}")
                if rule_id and rule_id not in backup_rule_ids:
                    print(f"   ⚠️ Warning: Requested rule {rule_id} not in backup rules list")
            else:
                print(f"🔄 Starting rule-specific rollback for {host}, rule: {backup_rule_id}")
                print(f"   Backup ID: {backup.get('backup_id')}")
                print(f"   Backup type: {backup.get('backup_type')}")
            
            rollback_details = {}
            backup_type = backup.get("backup_type", "unknown")
            
            # Rollback theo từng loại backup
            try:
                if backup_type == "batch":
                    # Batch backup - restore tất cả registry keys và policies từ backup data
                    print("🔄 Restoring batch backup - processing all registry keys and policies...")
                    # Restore registry keys (sẽ được xử lý ở phần dưới)
                    # Restore policies nếu có
                    if "net_accounts" in backup["data"] or "parsed_net_accounts" in backup["data"]:
                        self._restore_net_accounts(session, backup["data"], rollback_details)
                    if "guest_account_active" in backup["data"]:
                        self._restore_net_user_guest(session, backup["data"], rollback_details)
                    if "secedit_export" in backup["data"]:
                        self._restore_secedit_policy(session, backup["data"], rollback_details)
                    # Registry keys sẽ được restore ở phần dưới
                elif backup_type == "net_accounts":
                    self._restore_net_accounts(session, backup["data"], rollback_details)
                elif backup_type == "net_user":
                    self._restore_net_user_guest(session, backup["data"], rollback_details)
                elif backup_type == "secedit":
                    self._restore_secedit_policy(session, backup["data"], rollback_details)
                elif backup_type == "registry":
                    self._restore_registry_keys(session, backup["data"], rollback_details)
                elif backup_type == "netsh":
                    self._restore_netsh_firewall(session, backup["data"], rollback_details)
                elif backup_type == "auditpol":
                    self._restore_auditpol_policy(session, backup["data"], rollback_details)
                elif backup_type == "fallback":
                    self._restore_fallback_settings(session, backup["data"], rollback_details)
                else:
                    print(f"⚠️ Unknown backup type: {backup_type}, trying generic restore")
                    self._restore_generic(session, backup["data"], rollback_details)
                    
            except Exception as restore_error:
                print(f"⚠️ Error during specific restore: {restore_error}")
                rollback_details["restore_error"] = str(restore_error)
                # Thử restore generic như fallback
                self._restore_generic(session, backup["data"], rollback_details)
            
            # 5. Khôi phục Registry Keys nếu có - hỗ trợ cả dict và string format
            for key, reg_data in backup["data"].items():
                if not key.startswith("registry_") or key == "backup_info":
                    continue
                
                try:
                    reg_path = None
                    value_name = None
                    value_type = None
                    value_data = None
                    
                    # Parse từ backup_key: registry_HKLM_SYSTEM_CurrentControlSet_Services_LanmanServer_Parameters_value_name
                    # Format: registry_{normalized_path}_{value_name}
                    if isinstance(reg_data, dict):
                        # Format dict (từ single rule backup hoặc batch backup mới) - ƯU TIÊN ĐỌC TỪ DICT
                        reg_path = reg_data.get("path")
                        value_name = reg_data.get("value_name")
                        # Support cả "value_type" và "type" (backward compatibility)
                        value_type = reg_data.get("value_type") or reg_data.get("type", "REG_DWORD")
                        # Support cả "value_data" và "value" (backward compatibility)
                        value_data = reg_data.get("value_data") or reg_data.get("value")
                        exists = reg_data.get("exists", True)
                        
                        # Validate value_name từ dict - nếu None hoặc invalid, thử extract từ backup_key hoặc rule YAML
                        if not value_name or value_name == "None" or value_name.strip() == "":
                            print(f"   ⚠️ Invalid value_name '{value_name}' in backup data for key {key}, attempting to extract...")
                            # Thử extract từ backup_key
                            key_without_prefix = key.replace("registry_", "")
                            parts = key_without_prefix.split("_")
                            if len(parts) >= 2:
                                # Last part có thể là value_name
                                potential_value_name = parts[-1]
                                if potential_value_name and potential_value_name != "None":
                                    value_name = potential_value_name
                                    # Reconstruct path nếu chưa có
                                    if not reg_path:
                                        path_parts = parts[:-1]
                                        if path_parts and path_parts[0].startswith(("HKLM", "HKEY")):
                                            reg_path = "\\".join(path_parts)
                                        else:
                                            reg_path = "HKLM\\" + "\\".join(path_parts)
                                    print(f"   ✓ Extracted value_name '{value_name}' from backup key")
                            
                            # Nếu vẫn không có, thử extract từ rule YAML
                            if (not value_name or value_name == "None") and "rule_ids" in backup:
                                try:
                                    rules = load_rules()
                                    for rule_id in backup.get("rule_ids", []):
                                        for r in rules:
                                            if r.get("id") == rule_id:
                                                check_cmd = r.get("check", {}).get("winrm", "")
                                                reg_match = re.search(r'reg query\s+"([^"]+)"\s+/v\s+(\S+)', check_cmd)
                                                if reg_match:
                                                    rule_reg_path = reg_match.group(1)
                                                    rule_value_name = reg_match.group(2)
                                                    # Kiểm tra xem reg_path có match không
                                                    if not reg_path or rule_reg_path.replace('\\', '_').replace(':', '_') in key_without_prefix:
                                                        value_name = rule_value_name
                                                        reg_path = rule_reg_path
                                                        print(f"   ✓ Extracted value_name '{value_name}' from rule {rule_id}")
                                                        break
                                        if value_name and value_name != "None":
                                            break
                                except Exception as e:
                                    print(f"   ⚠️ Failed to extract value_name from rules: {e}")
                            
                            # Nếu vẫn không có value_name hợp lệ, skip
                            if not value_name or value_name == "None" or value_name.strip() == "":
                                print(f"   ⚠️ Cannot determine value_name for key {key}, skipping")
                                continue
                        
                        if not exists:
                            print(f"🔄 Registry key {reg_path}\\{value_name} did not exist originally, skipping restore")
                            rollback_details[key] = {
                                "status": "SKIPPED",
                                "message": "Registry key did not exist originally"
                            }
                            continue
                    elif isinstance(reg_data, str):
                        # Format string (từ batch backup cũ) - parse từ reg query output
                        # Example: "    RequireSecuritySignature    REG_DWORD    0x1"
                        # Extract từ backup_key: registry_HKLM_SYSTEM_CurrentControlSet_Services_LanmanServer_Parameters_RequireSecuritySignature
                        key_without_prefix = key.replace("registry_", "")
                        parts = key_without_prefix.split("_")
                        if len(parts) < 2:
                            print(f"   ⚠️ Invalid backup key format: {key}")
                            continue
                        
                        # Parse reg_data string để tìm value_name thực tế
                        # Format: "    value_name    REG_DWORD    0x1"
                        reg_line = reg_data.strip()
                        reg_parts = reg_line.split()
                        
                        if len(reg_parts) >= 3:
                            # value_name là phần đầu tiên (sau khi strip whitespace)
                            potential_value_name = reg_parts[0].strip()
                            
                            # Tìm REG_* type và value_data
                            reg_type_idx = None
                            for i, part in enumerate(reg_parts):
                                if part.startswith("REG_"):
                                    reg_type_idx = i
                                    value_type = part
                                    if i + 1 < len(reg_parts):
                                        value_data = reg_parts[i + 1]
                                    else:
                                        value_data = ""
                                    break
                            
                            if reg_type_idx is None:
                                # Fallback: assume REG_DWORD if not found
                                value_type = "REG_DWORD"
                                value_data = reg_parts[-1] if len(reg_parts) > 1 else ""
                            
                            # Xác định value_name và reg_path từ backup_key
                            # Backup key format: registry_HKLM_SYSTEM_CurrentControlSet_Control_Lsa_TurnOffAnonymousBlock
                            # Cần tìm value_name trong backup_key
                            if potential_value_name and potential_value_name != "None":
                                value_name = potential_value_name
                                # Tìm vị trí value_name trong backup_key
                                if value_name in key_without_prefix:
                                    value_name_idx = key_without_prefix.rfind(value_name)
                                    if value_name_idx > 0:
                                        # Extract path part (trước value_name)
                                        path_part = key_without_prefix[:value_name_idx].rstrip('_')
                                        path_parts = path_part.split('_')
                                        if path_parts and path_parts[0].startswith(("HKLM", "HKEY")):
                                            reg_path = "\\".join(path_parts)
                                        else:
                                            reg_path = "HKLM\\" + "\\".join(path_parts)
                                    else:
                                        # Fallback: use last part as value_name
                                        value_name = parts[-1]
                                        path_parts = parts[:-1]
                                        if path_parts and path_parts[0].startswith(("HKLM", "HKEY")):
                                            reg_path = "\\".join(path_parts)
                                        else:
                                            reg_path = "HKLM\\" + "\\".join(path_parts)
                                else:
                                    # value_name không có trong backup_key, dùng last part
                                    value_name = parts[-1]
                                    path_parts = parts[:-1]
                                    if path_parts and path_parts[0].startswith(("HKLM", "HKEY")):
                                        reg_path = "\\".join(path_parts)
                                    else:
                                        reg_path = "HKLM\\" + "\\".join(path_parts)
                            else:
                                # value_name là "None" hoặc không parse được từ reg_data, dùng last part của backup_key
                                value_name = parts[-1]
                                path_parts = parts[:-1]
                                if path_parts and path_parts[0].startswith(("HKLM", "HKEY")):
                                    reg_path = "\\".join(path_parts)
                                else:
                                    reg_path = "HKLM\\" + "\\".join(path_parts)
                                
                                # Nếu value_name là "None", có thể là do backup_key format sai hoặc key không tồn tại
                                # Thử tìm value_name từ các rules trong backup
                                if value_name == "None":
                                    print(f"   ⚠️ Warning: value_name is 'None' for key {key}, attempting to extract from backup metadata...")
                                    # Thử extract từ rule_ids trong backup
                                    if "rule_ids" in backup:
                                        # Load rules và tìm registry value_name
                                        try:
                                            rules = load_rules()
                                            for rule_id in backup.get("rule_ids", []):
                                                for r in rules:
                                                    if r.get("id") == rule_id:
                                                        check_cmd = r.get("check", {}).get("winrm", "")
                                                        reg_match = re.search(r'reg query\s+"([^"]+)"\s+/v\s+(\S+)', check_cmd)
                                                        if reg_match:
                                                            rule_reg_path = reg_match.group(1)
                                                            rule_value_name = reg_match.group(2)
                                                            # Kiểm tra xem reg_path có match không
                                                            if rule_reg_path.replace('\\', '_').replace(':', '_') in key_without_prefix:
                                                                value_name = rule_value_name
                                                                reg_path = rule_reg_path
                                                                print(f"   ✓ Extracted value_name '{value_name}' from rule {rule_id}")
                                                                break
                                                if value_name != "None":
                                                    break
                                        except Exception as e:
                                            print(f"   ⚠️ Failed to extract value_name from rules: {e}")
                                    
                                    # Nếu vẫn không tìm được, skip
                                    if value_name == "None":
                                        print(f"   ⚠️ Cannot determine value_name for key {key}, skipping")
                                        continue
                        else:
                            # Cannot parse reg_data, skip
                            print(f"   ⚠️ Invalid registry data format for key {key}: {reg_data[:100]}")
                            continue
                    else:
                        continue
                    
                    if not reg_path or not value_name or not value_data:
                        print(f"   ⚠️ Skipping {key}: missing path, value_name, or value_data")
                        continue
                    
                    print(f"🔄 Restoring registry key: {reg_path}\\{value_name} = {value_data} (type: {value_type})")
                    
                    # Restore registry value
                    if value_type == "REG_DWORD":
                        # Convert hex to decimal for reg add command
                        if isinstance(value_data, str) and value_data.startswith("0x"):
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
                        value_data_str = str(value_data)
                        if value_data_str in verify_output:
                            verified = True
                        elif value_type == "REG_DWORD" and str(decimal_value) in verify_output:
                            verified = True
                        elif value_type == "REG_DWORD" and f"0x{decimal_value:x}" in verify_output:
                            verified = True
                    
                    rollback_details[key] = {
                        "status": "RESTORED" if verified else "PARTIAL",
                        "command": cmd,
                        "result": result.std_out.decode() if result.status_code == 0 else result.std_err.decode(),
                        "exit_code": result.status_code,
                        "verified": verified,
                        "message": f"Registry key restored: {reg_path}\\{value_name} = {value_data}"
                    }
                    
                    if verified:
                        print(f"   ✓ Registry key restored: {reg_path}\\{value_name} = {value_data}")
                    else:
                        print(f"   ⚠️ Registry key restore verification failed: {reg_path}\\{value_name}")
                        print(f"      Expected: {value_data}, Got: {verify_output[:200] if verify_result.status_code == 0 else 'N/A'}")
                except Exception as e:
                    print(f"   ⚠️ Error restoring registry key {key}: {e}")
                    import traceback
                    traceback.print_exc()
                    rollback_details[key] = {
                        "status": "ERROR",
                        "error": str(e),
                        "message": f"Error restoring registry key: {e}"
                    }
            
            # Reload security policies nếu có registry keys được restore
            registry_keys_restored = sum(1 for k, v in rollback_details.items() 
                                       if k.startswith("registry_") and isinstance(v, dict) and v.get("status") == "RESTORED")
            if registry_keys_restored > 0:
                try:
                    print("🔄 Reloading security policies after registry changes...")
                    # Force policy update
                    gpupdate_result = session.run_cmd('gpupdate /force /wait:0')
                    if gpupdate_result.status_code == 0:
                        print("   ✓ Group policy updated")
                    else:
                        print(f"   ⚠️ Group policy update returned exit code {gpupdate_result.status_code}")
                    
                    # Reload registry (some settings require reboot, but we try to apply immediately)
                    reload_result = session.run_cmd('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v PendingFileRenameOperations /t REG_MULTI_SZ /d "" /f 2>nul')
                    print("   ✓ Registry changes applied")
                except Exception as e:
                    print(f"   ⚠️ Failed to reload policies (non-critical): {e}")
            
            # Lưu rollback log
            rollback_log = {
                "host": host,
                "backup_id": backup.get("backup_id", "unknown"),
                "rule_id": backup_rule_id,
                "timestamp": datetime.utcnow(),
                "type": "rollback_executed",
                "os_type": "windows",
                "rollback_details": rollback_details,
                "status": "SUCCESS" if all(d.get("status") in ["RESTORED", "SKIPPED"] for d in rollback_details.values() if isinstance(d, dict)) else "PARTIAL"
            }
            
            self.db.backups.insert_one(rollback_log)
            self._update_remediation_status(host, "ROLLED_BACK", rule_id=backup_rule_id)
            
            # Kiểm tra xem rollback có thành công không
            success_count = sum(1 for detail in rollback_details.values() 
                              if isinstance(detail, dict) and detail.get("status") in ["RESTORED", "SUCCESS", "SKIPPED"])
            total_count = len([d for d in rollback_details.values() if isinstance(d, dict)])
            
            if total_count == 0:
                final_status = "SKIPPED"
                message = f"No settings to restore for Windows host {host}"
            elif total_count > 0 and success_count == total_count:
                final_status = "SUCCESS"
                message = f"Rule-specific rollback completed successfully for Windows host {host}"
            elif success_count > 0:
                final_status = "PARTIAL"
                message = f"Rule-specific rollback partially completed for Windows host {host} ({success_count}/{total_count} operations succeeded)"
            else:
                final_status = "FAILED"
                message = f"Rule-specific rollback failed for Windows host {host} (0/{total_count} operations succeeded)"
            
            return {
                "status": final_status,
                "message": message,
                "host": host,
                "backup_id": backup.get("backup_id", "unknown"),
                "rule_id": backup_rule_id or backup_rule_ids,
                "backup_type": backup_type,
                "rollback_details": rollback_details,
                "summary": {
                    "total_operations": total_count,
                    "successful_operations": success_count,
                    "failed_operations": total_count - success_count
                }
            }
            
        except Exception as e:
            error_msg = f"Rollback failed: {str(e)}"
            print(f"❌ Rule-specific rollback failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                "status": "FAILED",
                "message": error_msg,
                "host": host,
                "rule_id": rule_id,
                "error": "ROLLBACK_EXECUTION_ERROR",
                "error_details": str(e),
                "rollback_details": {}
            }
    
    def _restore_registry_keys(self, session: winrm.Session, backup_data: Dict, 
                              rollback_details: Dict):
        """Khôi phục registry keys từ backup."""
        registry_restored = 0
        registry_failed = 0
        
        for key, reg_data in backup_data.items():
            if key.startswith("registry_"):
                try:
                    if isinstance(reg_data, dict):
                        if reg_data.get("status") == "KEY_NOT_EXIST":
                            # Key không tồn tại trong backup
                            reg_path = reg_data.get("path")
                            value_name = reg_data.get("value_name")
                            if reg_path and value_name:
                                # Kiểm tra xem key có tồn tại không
                                check_result = session.run_cmd(f'reg query "{reg_path}" /v {value_name}')
                                if check_result.status_code == 0:
                                    # Key exists, delete it
                                    cmd = f'reg delete "{reg_path}" /v {value_name} /f'
                                    result = session.run_cmd(cmd)
                                    status = "DELETED" if result.status_code == 0 else "DELETE_FAILED"
                                else:
                                    # Key không tồn tại, không cần làm gì
                                    status = "NOT_EXIST"
                                    result = type('obj', (object,), {'status_code': 0})()
                        else:
                            # Khôi phục giá trị registry
                            reg_path = reg_data.get("path")
                            value_name = reg_data.get("value_name")
                            reg_value = reg_data.get("value")
                            reg_type = reg_data.get("type", "REG_DWORD")
                            
                            if all([reg_path, value_name, reg_value]):
                                # Đảm bảo reg_path tồn tại
                                session.run_cmd(f'reg add "{reg_path}" /f 2>nul')
                                
                                # Set giá trị
                                cmd = f'reg add "{reg_path}" /v {value_name} /t {reg_type} /d {reg_value} /f'
                                result = session.run_cmd(cmd)
                                status = "RESTORED" if result.status_code == 0 else "RESTORE_FAILED"
                            else:
                                status = "INVALID_DATA"
                                result = type('obj', (object,), {'status_code': 1})()
                        
                        rollback_details[key] = {
                            "operation": "registry_restore",
                            "status": "SUCCESS" if result.status_code == 0 else "FAILED",
                            "details": {
                                "path": reg_path,
                                "value_name": value_name,
                                "command": cmd if 'cmd' in locals() else "N/A",
                                "exit_code": result.status_code,
                                "output": result.std_out.decode()[:200] if result.status_code == 0 else result.std_err.decode()[:200]
                            }
                        }
                        
                        if result.status_code == 0:
                            registry_restored += 1
                        else:
                            registry_failed += 1
                            
                except Exception as e:
                    rollback_details[key] = {
                        "operation": "registry_restore",
                        "status": "ERROR",
                        "error": str(e)
                    }
                    registry_failed += 1
        
        print(f"   Registry restore: {registry_restored} successful, {registry_failed} failed")
    
    def _restore_net_accounts(self, session: winrm.Session, backup_data: Dict, rollback_details: Dict):
        """Khôi phục net accounts settings."""
        try:
            if "parsed_net_accounts" in backup_data:
                parsed = backup_data["parsed_net_accounts"]
                restored = 0
                
                for setting, value in parsed.items():
                    try:
                        if setting == "PasswordHistorySize":
                            cmd = f'net accounts /uniquepw:{value}'
                        elif setting == "MaximumPasswordAge":
                            cmd = f'net accounts /maxpwage:{value}'
                        elif setting == "MinimumPasswordLength":
                            cmd = f'net accounts /minpwlen:{value}'
                        else:
                            continue
                        
                        result = session.run_cmd(cmd)
                        rollback_details[f"net_accounts_{setting}"] = {
                            "operation": "net_accounts_restore",
                            "status": "SUCCESS" if result.status_code == 0 else "FAILED",
                            "details": {
                                "setting": setting,
                                "value": value,
                                "command": cmd,
                                "exit_code": result.status_code,
                                "output": result.std_out.decode()[:200] if result.status_code == 0 else result.std_err.decode()[:200]
                            }
                        }
                        
                        if result.status_code == 0:
                            restored += 1
                            
                    except Exception as e:
                        rollback_details[f"net_accounts_{setting}_error"] = {
                            "operation": "net_accounts_restore",
                            "status": "ERROR",
                            "error": str(e)
                        }
                
                print(f"   Net accounts restore: {restored} settings restored")
                
        except Exception as e:
            print(f"   ⚠️ Failed to restore net accounts: {e}")
            rollback_details["net_accounts_error"] = {
                "operation": "net_accounts_restore",
                "status": "ERROR",
                "error": str(e)
            }
    
    def _restore_generic(self, session: winrm.Session, backup_data: Dict, rollback_details: Dict):
        """Generic restore khi không có restore method cụ thể."""
        print("🔧 Performing generic restore from backup data...")
        
        # Kiểm tra và restore từng loại data trong backup
        if "net_accounts" in backup_data:
            self._restore_net_accounts(session, backup_data, rollback_details)
        
        # Tìm và restore registry keys
        for key, value in backup_data.items():
            if key.startswith("registry_"):
                self._restore_registry_keys(session, {key: value}, rollback_details)
        
        print("   Generic restore completed")
    
    def _restore_net_user_guest(self, session: winrm.Session, backup_data: Dict, rollback_details: Dict):
        """Khôi phục guest account."""
        try:
            if "guest_account_active" in backup_data:
                guest_active = backup_data["guest_account_active"]
                value = "yes" if guest_active else "no"
                cmd = f'net user guest /active:{value}'
                result = session.run_cmd(cmd)
                
                rollback_details["guest_account"] = {
                    "operation": "guest_account_restore",
                    "status": "SUCCESS" if result.status_code == 0 else "FAILED",
                    "details": {
                        "active": guest_active,
                        "command": cmd,
                        "exit_code": result.status_code,
                        "output": result.std_out.decode()[:200] if result.status_code == 0 else result.std_err.decode()[:200]
                    }
                }
                print(f"   Guest account restored: active={guest_active}")
                
        except Exception as e:
            print(f"   ⚠️ Failed to restore guest account: {e}")
            rollback_details["guest_account_error"] = {
                "operation": "guest_account_restore",
                "status": "ERROR",
                "error": str(e)
            }
    
    def _restore_fallback_settings(self, session: winrm.Session, backup_data: Dict, rollback_details: Dict):
        """Fallback restore."""
        print("🔧 Performing fallback restore...")
        
        # Thử restore net accounts
        self._restore_net_accounts(session, backup_data, rollback_details)
        
        # Thử restore guest account
        self._restore_net_user_guest(session, backup_data, rollback_details)
        
        print("   Fallback restore completed")
    
    def _update_remediation_status(self, host: str, status: str, rule_id: Optional[str] = None):
        """Cập nhật trạng thái remediation log với rule_id."""
        try:
            update_filter = {"host": host, "client_type": "windows"}
            if rule_id:
                update_filter["rule_id"] = rule_id
            
            self.db.remediations.update_one(
                update_filter,
                {"$set": {"rollback_status": status, "rollback_time": datetime.utcnow()}},
                upsert=False
            )
        except Exception as e:
            print(f"⚠️ Failed to update remediation status: {e}")
    
    def get_backups(self, host: str) -> list:
        """Lấy danh sách rule backups cho một Windows host (chỉ pre_remediation_backup)."""
        try:
            backups = list(self.db.backups.find(
                {
                    "host": host,
                    "type": "pre_remediation_backup",
                    "os_type": "windows"
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
