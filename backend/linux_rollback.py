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
        sudo_password: Optional[str] = None
    ) -> Optional[str]:
        """Tạo backup trạng thái hiện tại trước khi remediation."""
        try:
            print(f"🛡️ Starting backup for Linux host: {host}")
            
            ssh = ssh_connect(host, username, key_path, password)
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "pre_remediation_backup",
                "os_type": "linux",
                "backup_id": f"backup_{int(datetime.utcnow().timestamp())}",
                "data": {}
            }
            
            try:
                # 1. Backup SSH Configuration (/etc/ssh/sshd_config) - CHỈ FILE NÀY LÀ QUAN TRỌNG
                try:
                    print("🔍 Backing up SSH configuration...")
                    backup_script = """
                    timeout 10 sh -c 'if [ -f /etc/ssh/sshd_config ]; then head -c 100000 /etc/ssh/sshd_config; fi'
                    """
                    result = run_bash_check_stdin(
                        ssh, backup_script, use_sudo=False, timeout=15
                    )
                    
                    if result["exit_status"] == 0 and result["stdout"]:
                        # Giới hạn kích thước backup (max 100KB)
                        content = result["stdout"][:100000]
                        backup_data["data"]["sshd_config"] = content
                        print(f"   ✓ SSH config backed up ({len(content)} bytes)")
                    else:
                        # Thử với sudo nếu cần
                        result_sudo = run_bash_check_stdin(
                            ssh, backup_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                        )
                        if result_sudo["exit_status"] == 0 and result_sudo["stdout"]:
                            content = result_sudo["stdout"][:100000]
                            backup_data["data"]["sshd_config"] = content
                            print(f"   ✓ SSH config backed up with sudo ({len(content)} bytes)")
                except Exception as e:
                    print(f"   ⚠️ Failed to backup SSH config: {e}")
                
                # 2. CHỈ BACKUP CÁC FILE THỰC SỰ CẦN THIẾT (KHÔNG BACKUP /etc/shadow, /etc/sudoers - quá nguy hiểm)
                # Chỉ backup những file nhỏ và an toàn
                safe_files = [
                    "/etc/passwd",  # File nhỏ, chỉ thông tin user
                    "/etc/group",   # File nhỏ, chỉ thông tin group
                ]
                
                for file_path in safe_files:
                    try:
                        # Timeout 10s cho mỗi file, giới hạn 50KB
                        backup_script = f"""
                        timeout 10 sh -c 'if [ -f {file_path} ]; then head -c 50000 {file_path}; fi'
                        """
                        result = run_bash_check_stdin(
                            ssh, backup_script, use_sudo=False, timeout=15
                        )
                        if result["exit_status"] == 0 and result["stdout"]:
                            file_key = file_path.replace("/", "_").replace(".", "_")
                            backup_data["data"][f"file_{file_key}"] = result["stdout"][:50000]
                            print(f"   ✓ {file_path} backed up ({len(result['stdout'])} bytes)")
                        else:
                            print(f"   ⚠️ Skipped {file_path} (timeout or error)")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup {file_path}: {e}")
                
                # 3. Backup current SSH service status (với timeout)
                try:
                    status_script = """
                    timeout 5 sh -c 'systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown"'
                    """
                    result = run_bash_check_stdin(ssh, status_script, use_sudo=False, timeout=10)
                    if result["exit_status"] == 0:
                        backup_data["data"]["ssh_service_status"] = result["stdout"].strip()
                except Exception as e:
                    print(f"   ⚠️ Failed to get SSH service status: {e}")
                
                # Thêm thông tin backup
                backup_data["data"]["backup_info"] = {
                    "backup_time": str(datetime.utcnow()),
                    "host": host,
                    "username": username,
                    "notes": "Backup created before Linux remediation - Only SSH config and safe files",
                    "backup_scope": "Limited - SSH config, /etc/passwd, /etc/group only (NOT full system backup)"
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
        """Lấy danh sách backups cho một Linux host."""
        try:
            backups = list(self.db.backups.find(
                {"host": host, "os_type": "linux"},
                sort=[("timestamp", -1)]
            ))
            for backup in backups:
                backup["_id"] = str(backup["_id"])
            return backups
        except Exception as e:
            print(f"❌ Failed to get backups: {e}")
            return []


linux_rollback_manager = LinuxRollbackManager()

