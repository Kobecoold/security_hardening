"""Rollback module for Linux security hardening."""
import paramiko
from datetime import datetime
from typing import Dict, Optional, List, Any
from database import db
from linux_audit import ssh_connect, run_bash_check_stdin
import re


class LinuxRollbackManager:
    """Quản lý rollback cho Linux."""
    
    def __init__(self):
        self.db = db
    
    def create_backup(
        self, 
        host: str, 
        username: str,
        key_path: str = "",
        password: Optional[str] = None,
        sudo_password: Optional[str] = None,
        rule_id: Optional[str] = None
    ) -> Optional[str]:
        """Tạo backup trạng thái hiện tại trước khi remediation - chỉ backup những gì rule sẽ sửa."""
        try:
            print(f"🛡️ Starting backup for Linux host: {host}")
            
            ssh = ssh_connect(host, username, key_path, password)
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "pre_remediation_backup",
                "os_type": "linux",
                "backup_id": f"backup_{int(datetime.utcnow().timestamp())}",
                "rule_id": rule_id,  # Lưu rule_id để biết backup này dành cho rule nào
                "data": {}
            }
            
            # Xác định files cần backup dựa vào rule_id
            files_to_backup = self._get_files_to_backup_for_rule(rule_id)
            
            try:
                # Backup các file mà remediation script sẽ sửa
                for file_path in files_to_backup:
                    try:
                        print(f"🔍 Backing up {file_path}...")
                        # Backup file content
                        backup_script = f"""
                        timeout 10 sh -c 'if [ -f {file_path} ]; then head -c 100000 {file_path}; fi'
                        """
                        result = run_bash_check_stdin(
                            ssh, backup_script, use_sudo=False, timeout=15
                        )
                        
                        if result["exit_status"] == 0 and result["stdout"]:
                            content = result["stdout"][:100000]
                            file_key = file_path.replace("/", "_").replace(".", "_")
                            backup_data["data"][f"file_{file_key}"] = content
                            print(f"   ✓ {file_path} backed up ({len(content)} bytes)")
                        else:
                            # Thử với sudo nếu cần
                            result_sudo = run_bash_check_stdin(
                                ssh, backup_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result_sudo["exit_status"] == 0 and result_sudo["stdout"]:
                                content = result_sudo["stdout"][:100000]
                                file_key = file_path.replace("/", "_").replace(".", "_")
                                backup_data["data"][f"file_{file_key}"] = content
                                print(f"   ✓ {file_path} backed up with sudo ({len(content)} bytes)")
                            else:
                                print(f"   ⚠️ Skipped {file_path} (not accessible)")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup {file_path}: {e}")
                
                # Backup file permissions nếu rule sửa permissions
                if rule_id and any(x in rule_id for x in ['1.1.', '1.2.', '1.3.', '1.4.']):
                    for file_path in files_to_backup:
                        try:
                            print(f"🔍 Backing up permissions for {file_path}...")
                            perm_script = f"""
                            timeout 5 sh -c 'if [ -e {file_path} ]; then stat -c "%a %U:%G" {file_path} 2>/dev/null || stat -f "%OLp %Su:%Sg" {file_path} 2>/dev/null || echo "unknown"; fi'
                            """
                            result = run_bash_check_stdin(ssh, perm_script, use_sudo=False, timeout=10)
                            if result["exit_status"] == 0 and result["stdout"]:
                                file_key = file_path.replace("/", "_").replace(".", "_")
                                backup_data["data"][f"perms_{file_key}"] = result["stdout"].strip()
                                print(f"   ✓ Permissions backed up for {file_path}")
                        except Exception as e:
                            print(f"   ⚠️ Failed to backup permissions for {file_path}: {e}")
                
                # Backup service status nếu rule sửa service
                if rule_id and '5.2.' in rule_id:
                    try:
                        print("🔍 Backing up SSH service status...")
                        status_script = """
                        timeout 5 sh -c 'systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown"'
                        """
                        result = run_bash_check_stdin(ssh, status_script, use_sudo=False, timeout=10)
                        if result["exit_status"] == 0:
                            backup_data["data"]["ssh_service_status"] = result["stdout"].strip()
                            print(f"   ✓ SSH service status backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to get SSH service status: {e}")
                
                # Thêm thông tin backup
                backup_data["data"]["backup_info"] = {
                    "backup_time": str(datetime.utcnow()),
                    "host": host,
                    "username": username,
                    "rule_id": rule_id,
                    "notes": f"Backup created before remediation for rule {rule_id} - Only files that will be modified",
                    "backup_scope": f"Rule-specific backup for {rule_id} - Only files/configs that remediation will modify"
                }
                
            finally:
                ssh.close()
            
            # Save to MongoDB
            backup_id = self._save_backup(backup_data)
            print(f"✅ Backup created for {host}: {backup_id}")
            
            return backup_id
            
        except Exception as e:
            print(f"❌ Backup creation failed: {e}")
            import traceback
            traceback.print_exc()
            # Không raise exception để remediation vẫn chạy được
            return None
    
    def _get_files_to_backup_for_rule(self, rule_id: Optional[str]) -> List[str]:
        """Xác định các file cần backup dựa vào rule_id."""
        if not rule_id:
            # Fallback: backup SSH config nếu không có rule_id
            return ["/etc/ssh/sshd_config"]
        
        files_to_backup = []
        
        # Rule về SSH (5.2.x)
        if '5.2.' in rule_id:
            files_to_backup.append("/etc/ssh/sshd_config")
        
        # Rule về file system mounts (1.1.x)
        if '1.1.' in rule_id:
            # Các rule về /tmp, /var/tmp, /home, etc.
            if 'tmp' in rule_id.lower():
                files_to_backup.append("/etc/fstab")
            elif 'home' in rule_id.lower():
                files_to_backup.append("/etc/fstab")
        
        # Rule về file permissions (1.2.x, 1.3.x, 1.4.x)
        if any(x in rule_id for x in ['1.2.', '1.3.', '1.4.']):
            # Parse rule để tìm file cụ thể
            if 'passwd' in rule_id.lower() or '1.1.1' in rule_id:
                files_to_backup.append("/etc/passwd")
            elif 'group' in rule_id.lower() or '1.1.2' in rule_id:
                files_to_backup.append("/etc/group")
            elif 'shadow' in rule_id.lower():
                files_to_backup.append("/etc/shadow")
            elif 'gshadow' in rule_id.lower():
                files_to_backup.append("/etc/gshadow")
            elif 'fstab' in rule_id.lower():
                files_to_backup.append("/etc/fstab")
            elif 'crontab' in rule_id.lower():
                files_to_backup.append("/etc/crontab")
            elif 'hosts' in rule_id.lower():
                files_to_backup.append("/etc/hosts")
            elif 'issue' in rule_id.lower():
                files_to_backup.append("/etc/issue")
                files_to_backup.append("/etc/issue.net")
        
        # Rule về network (3.x)
        if rule_id.startswith('cis-') and any(x in rule_id for x in ['3.1.', '3.2.', '3.3.', '3.4.', '3.5.']):
            if 'sshd' in rule_id.lower() or 'ssh' in rule_id.lower():
                files_to_backup.append("/etc/ssh/sshd_config")
        
        # Rule về logging (4.x)
        if rule_id.startswith('cis-') and '4.' in rule_id:
            if 'rsyslog' in rule_id.lower():
                files_to_backup.append("/etc/rsyslog.conf")
            elif 'logrotate' in rule_id.lower():
                files_to_backup.append("/etc/logrotate.conf")
        
        # Rule về access control (5.x)
        if rule_id.startswith('cis-') and '5.' in rule_id:
            if 'sshd' in rule_id.lower() or 'ssh' in rule_id.lower():
                files_to_backup.append("/etc/ssh/sshd_config")
            elif 'sudo' in rule_id.lower():
                files_to_backup.append("/etc/sudoers")
        
        # Nếu không tìm thấy file cụ thể, backup SSH config (phổ biến nhất)
        if not files_to_backup:
            files_to_backup.append("/etc/ssh/sshd_config")
        
        return list(set(files_to_backup))  # Remove duplicates
    
    def _save_backup(self, backup_data: Dict) -> str:
        """Lưu backup vào MongoDB."""
        try:
            result = self.db.backups.insert_one(backup_data)
            return str(result.inserted_id)
        except Exception as e:
            print(f"❌ Failed to save backup to MongoDB: {e}")
            return f"backup_error_{int(datetime.utcnow().timestamp())}"
    
    def execute_rollback(
        self,
        host: str,
        username: str,
        key_path: str = "",
        password: Optional[str] = None,
        sudo_password: Optional[str] = None,
        backup_id: Optional[str] = None
    ) -> Dict:
        """Thực hiện rollback dựa trên backup."""
        try:
            # Tìm backup
            if backup_id:
                backup = self.db.backups.find_one({"backup_id": backup_id, "host": host})
            else:
                backup = self.db.backups.find_one(
                    {"host": host, "type": "pre_remediation_backup", "os_type": "linux"},
                    sort=[("timestamp", -1)]
                )
            
            if not backup:
                return {
                    "status": "SKIPPED",
                    "message": f"No backup found for Linux host {host}",
                    "host": host
                }
            
            print(f"🔄 Starting rollback for Linux host {host} using backup: {backup.get('backup_id', 'unknown')}")
            
            ssh = ssh_connect(host, username, key_path, password)
            rollback_details = {}
            
            try:
                # 1. Khôi phục SSH Configuration
                if "sshd_config" in backup.get("data", {}):
                    try:
                        print("🔄 Restoring SSH configuration...")
                        sshd_config_content = backup["data"]["sshd_config"]
                        
                        # Tạo script để restore file
                        restore_script = f"""
cat > /tmp/sshd_config_restore << 'EOF'
{sshd_config_content}
EOF
cp /tmp/sshd_config_restore /etc/ssh/sshd_config
chmod 644 /etc/ssh/sshd_config
rm /tmp/sshd_config_restore
"""
                        result = run_bash_check_stdin(
                            ssh, restore_script, use_sudo=True, sudo_password=sudo_password
                        )
                        
                        if result["exit_status"] == 0:
                            # Reload SSH service
                            reload_script = "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload || true"
                            reload_result = run_bash_check_stdin(
                                ssh, reload_script, use_sudo=True, sudo_password=sudo_password
                            )
                            
                            rollback_details["sshd_config"] = {
                                "status": "RESTORED",
                                "reload_status": reload_result.get("exit_status", 0),
                                "message": "SSH configuration restored successfully"
                            }
                            print("   ✓ SSH config restored")
                        else:
                            rollback_details["sshd_config"] = {
                                "status": "FAILED",
                                "error": result["stderr"],
                                "message": "Failed to restore SSH configuration"
                            }
                    except Exception as e:
                        rollback_details["sshd_config"] = {
                            "status": "ERROR",
                            "error": str(e),
                            "message": f"Error restoring SSH config: {e}"
                        }
                
                # 2. Khôi phục các file quan trọng khác nếu cần
                # (Có thể mở rộng sau)
                
            finally:
                ssh.close()
            
            # Lưu rollback log
            rollback_log = {
                "host": host,
                "backup_id": backup.get("backup_id", "unknown"),
                "timestamp": datetime.utcnow(),
                "type": "rollback_executed",
                "os_type": "linux",
                "rollback_details": rollback_details,
                "status": "SUCCESS" if all(d.get("status") in ["RESTORED", "SKIPPED"] for d in rollback_details.values()) else "PARTIAL"
            }
            
            self.db.backups.insert_one(rollback_log)
            self._update_remediation_status(host, "ROLLED_BACK")
            
            return {
                "status": "SUCCESS",
                "message": f"Rollback completed for Linux host {host}",
                "backup_id": backup.get("backup_id", "unknown"),
                "rollback_details": rollback_details
            }
            
        except Exception as e:
            print(f"❌ Rollback failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                "status": "FAILED",
                "message": f"Rollback failed: {str(e)}",
                "host": host
            }
    
    def _update_remediation_status(self, host: str, status: str):
        """Cập nhật trạng thái remediation log."""
        try:
            self.db.remediations.update_one(
                {"host": host, "client_type": "linux"},
                {"$set": {"rollback_status": status, "rollback_time": datetime.utcnow()}},
                upsert=False
            )
        except Exception as e:
            print(f"⚠️ Failed to update remediation status: {e}")
    
    def get_backups(self, host: str) -> list:
        """Lấy danh sách rule backups cho một Linux host (chỉ pre_remediation_backup)."""
        try:
            backups = list(self.db.backups.find(
                {
                    "host": host,
                    "os_type": "linux",
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


linux_rollback_manager = LinuxRollbackManager()

