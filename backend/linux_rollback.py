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
                
                # Backup file permissions cho TẤT CẢ files (không chỉ một số rules)
                for file_path in files_to_backup:
                    try:
                        print(f"🔍 Backing up permissions for {file_path}...")
                        perm_script = f"""
                        timeout 5 sh -c 'if [ -e {file_path} ]; then stat -c "%a %U:%G" {file_path} 2>/dev/null || stat -f "%OLp %Su:%Sg" {file_path} 2>/dev/null || echo "unknown"; fi'
                        """
                        # Try with sudo first for protected files
                        result = run_bash_check_stdin(ssh, perm_script, use_sudo=True, sudo_password=sudo_password, timeout=10)
                        if result["exit_status"] != 0 or not result["stdout"] or result["stdout"].strip() == "unknown":
                            # Fallback to non-sudo
                            result = run_bash_check_stdin(ssh, perm_script, use_sudo=False, timeout=10)
                        if result["exit_status"] == 0 and result["stdout"] and result["stdout"].strip() != "unknown":
                            file_key = file_path.replace("/", "_").replace(".", "_")
                            backup_data["data"][f"perms_{file_key}"] = result["stdout"].strip()
                            print(f"   ✓ Permissions backed up for {file_path}: {result['stdout'].strip()}")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup permissions for {file_path}: {e}")
                
                # Backup sysctl settings nếu rule sửa sysctl (network rules 3.x)
                if rule_id and any(x in rule_id for x in ['3.1.', '3.2.', '3.3.']):
                    try:
                        print("🔍 Backing up sysctl settings...")
                        # Backup /etc/sysctl.conf
                        if "/etc/sysctl.conf" not in files_to_backup:
                            files_to_backup.append("/etc/sysctl.conf")
                        
                        # Backup current sysctl values (runtime)
                        sysctl_script = """
                        timeout 10 sh -c 'sysctl -a 2>/dev/null | grep -E "^(net\.ipv4\.|net\.ipv6\.)" | head -50'
                        """
                        result = run_bash_check_stdin(ssh, sysctl_script, use_sudo=True, sudo_password=sudo_password, timeout=15)
                        if result["exit_status"] == 0 and result["stdout"]:
                            backup_data["data"]["sysctl_runtime"] = result["stdout"][:50000]  # Limit size
                            print(f"   ✓ Sysctl runtime values backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup sysctl settings: {e}")
                
                # Backup mount options nếu rule sửa mounts (filesystem rules 1.1.x)
                if rule_id and '1.1.' in rule_id:
                    try:
                        print("🔍 Backing up mount information...")
                        mount_script = """
                        timeout 10 sh -c 'mount | grep -E "\\s/(tmp|var/tmp|home)\\s"'
                        """
                        result = run_bash_check_stdin(ssh, mount_script, use_sudo=False, timeout=10)
                        if result["exit_status"] == 0 and result["stdout"]:
                            backup_data["data"]["mount_info"] = result["stdout"][:10000]
                            print(f"   ✓ Mount information backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup mount info: {e}")
                
                # Backup service status nếu rule sửa service (2.x, 4.x, 5.x)
                if rule_id and any(x in rule_id for x in ['2.', '4.', '5.']):
                    # Detect service name from rule
                    service_name = None
                    if 'ssh' in rule_id.lower() or '5.2.' in rule_id or '5.3.' in rule_id:
                        service_name = "ssh"
                    elif 'avahi' in rule_id.lower() or '2.2.2' in rule_id:
                        service_name = "avahi-daemon"
                    elif 'x11' in rule_id.lower() or '2.2.1' in rule_id:
                        service_name = "xserver-xorg"
                    elif 'cups' in rule_id.lower() or '2.2.3' in rule_id:
                        service_name = "cups"
                    elif 'audit' in rule_id.lower() or '4.1.' in rule_id:
                        service_name = "auditd"
                    
                    if service_name:
                        try:
                            print(f"🔍 Backing up {service_name} service status...")
                            status_script = f"""
                            timeout 5 sh -c 'systemctl is-active {service_name} 2>/dev/null || systemctl is-active {service_name}d 2>/dev/null || echo "unknown"'
                            """
                            result = run_bash_check_stdin(ssh, status_script, use_sudo=False, timeout=10)
                            if result["exit_status"] == 0:
                                backup_data["data"][f"{service_name}_service_status"] = result["stdout"].strip()
                                print(f"   ✓ {service_name} service status backed up: {result['stdout'].strip()}")
                            
                            # Also backup enabled status
                            enabled_script = f"""
                            timeout 5 sh -c 'systemctl is-enabled {service_name} 2>/dev/null || systemctl is-enabled {service_name}d 2>/dev/null || echo "unknown"'
                            """
                            result_enabled = run_bash_check_stdin(ssh, enabled_script, use_sudo=False, timeout=10)
                            if result_enabled["exit_status"] == 0:
                                backup_data["data"][f"{service_name}_service_enabled"] = result_enabled["stdout"].strip()
                                print(f"   ✓ {service_name} service enabled status backed up: {result_enabled['stdout'].strip()}")
                        except Exception as e:
                            print(f"   ⚠️ Failed to backup {service_name} service status: {e}")
                
                # Backup package installation status nếu rule remove packages (2.x services)
                if rule_id and '2.2.' in rule_id:
                    # Detect package name from rule
                    package_name = None
                    if 'avahi' in rule_id.lower() or '2.2.2' in rule_id:
                        package_name = "avahi-daemon"
                    elif 'cups' in rule_id.lower() or '2.2.3' in rule_id:
                        package_name = "cups"
                    elif 'dhcp' in rule_id.lower() or '2.2.4' in rule_id:
                        package_name = "isc-dhcp-server"
                    elif 'ldap' in rule_id.lower() or '2.2.5' in rule_id:
                        package_name = "slapd"
                    elif 'nfs' in rule_id.lower() or '2.2.6' in rule_id:
                        package_name = "nfs-kernel-server"
                    elif 'rpcbind' in rule_id.lower() or '2.2.7' in rule_id:
                        package_name = "rpcbind"
                    elif 'xinetd' in rule_id.lower() or '2.1.1' in rule_id:
                        package_name = "xinetd"
                    
                    if package_name:
                        try:
                            print(f"🔍 Backing up {package_name} package status...")
                            pkg_script = f"""
                            timeout 10 sh -c 'dpkg -l {package_name} 2>/dev/null | grep "^ii" || echo "not_installed"'
                            """
                            result = run_bash_check_stdin(ssh, pkg_script, use_sudo=False, timeout=10)
                            if result["exit_status"] == 0:
                                backup_data["data"][f"{package_name}_installed"] = result["stdout"].strip()
                                print(f"   ✓ {package_name} package status backed up")
                        except Exception as e:
                            print(f"   ⚠️ Failed to backup {package_name} package status: {e}")
                
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
            if '1.4.1' in rule_id or 'bootloader' in rule_id.lower() or 'grub' in rule_id.lower():
                # Rule 1.4.1: Bootloader permissions
                files_to_backup.append("/boot/grub/grub.cfg")
            elif 'passwd' in rule_id.lower() or '1.1.1' in rule_id:
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
        
        # Rule về network (3.x) - sửa sysctl
        if rule_id.startswith('cis-') and any(x in rule_id for x in ['3.1.', '3.2.', '3.3.', '3.4.', '3.5.']):
            # Network rules sửa /etc/sysctl.conf
            files_to_backup.append("/etc/sysctl.conf")
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
                # 1. Khôi phục SSH Configuration (check cả 2 keys: "sshd_config" và "file_etc_ssh_sshd_config")
                sshd_config_content = None
                sshd_config_key = None
                
                # Check old format first (direct key)
                if "sshd_config" in backup.get("data", {}):
                    sshd_config_content = backup["data"]["sshd_config"]
                    sshd_config_key = "sshd_config"
                # Check new format (file_ prefix)
                elif "file_etc_ssh_sshd_config" in backup.get("data", {}):
                    sshd_config_content = backup["data"]["file_etc_ssh_sshd_config"]
                    sshd_config_key = "file_etc_ssh_sshd_config"
                
                if sshd_config_content:
                    try:
                        print("🔄 Restoring SSH configuration...")
                        
                        # Get original permissions if available
                        sshd_perms_key = "perms_etc_ssh_sshd_config" if sshd_config_key == "file_etc_ssh_sshd_config" else "perms_sshd_config"
                        sshd_perms_data = backup.get("data", {}).get(sshd_perms_key, "")
                        default_perms = "644"
                        default_owner = "root"
                        default_group = "root"
                        
                        if sshd_perms_data and sshd_perms_data != "unknown":
                            parts = sshd_perms_data.split()
                            if len(parts) >= 2:
                                default_perms = parts[0]
                                owner_group = parts[1]
                                if ":" in owner_group:
                                    default_owner, default_group = owner_group.split(":", 1)
                                else:
                                    default_owner = owner_group
                                    default_group = owner_group
                        
                        # Tạo script để restore file với original permissions
                        restore_script = f"""
cat > /tmp/sshd_config_restore << 'EOF'
{sshd_config_content}
EOF
cp /tmp/sshd_config_restore /etc/ssh/sshd_config
chmod {default_perms} /etc/ssh/sshd_config
chown {default_owner}:{default_group} /etc/ssh/sshd_config
rm /tmp/sshd_config_restore
"""
                        result = run_bash_check_stdin(
                            ssh, restore_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                        )
                        
                        if result["exit_status"] == 0:
                            # Reload SSH service
                            reload_script = "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload || true"
                            reload_result = run_bash_check_stdin(
                                ssh, reload_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            
                            rollback_details["/etc/ssh/sshd_config"] = {
                                "status": "RESTORED",
                                "content_restored": True,
                                "permissions": default_perms,
                                "owner": default_owner,
                                "group": default_group,
                                "reload_status": reload_result.get("exit_status", 0),
                                "message": f"SSH configuration restored: {default_perms} {default_owner}:{default_group}"
                            }
                            print(f"   ✓ SSH config restored: {default_perms} {default_owner}:{default_group}")
                        else:
                            rollback_details["/etc/ssh/sshd_config"] = {
                                "status": "FAILED",
                                "error": result.get("stderr", ""),
                                "message": "Failed to restore SSH configuration"
                            }
                            print(f"   ⚠️ Failed to restore SSH config: {result.get('stderr', '')}")
                    except Exception as e:
                        rollback_details["/etc/ssh/sshd_config"] = {
                            "status": "ERROR",
                            "error": str(e),
                            "message": f"Error restoring SSH config: {e}"
                        }
                        print(f"   ⚠️ Error restoring SSH config: {e}")
                
                # 2. Khôi phục các file khác (không phải SSH config)
                rule_id = backup.get("rule_id", "")
                
                # Map file keys to actual file paths
                file_key_to_path = {}
                for file_key in backup.get("data", {}).keys():
                    if file_key.startswith("file_") and not file_key.startswith("file_etc_ssh_sshd_config"):
                        # Extract file path từ key
                        if "boot_grub_grub_cfg" in file_key:
                            file_path = "/boot/grub/grub.cfg"
                        elif "etc_passwd" in file_key:
                            file_path = "/etc/passwd"
                        elif "etc_group" in file_key:
                            file_path = "/etc/group"
                        elif "etc_fstab" in file_key:
                            file_path = "/etc/fstab"
                        elif "etc_crontab" in file_key:
                            file_path = "/etc/crontab"
                        elif "etc_hosts" in file_key:
                            file_path = "/etc/hosts"
                        elif "etc_issue" in file_key:
                            if "issue_net" in file_key:
                                file_path = "/etc/issue.net"
                            else:
                                file_path = "/etc/issue"
                        else:
                            # Try to reconstruct from key
                            file_path = file_key.replace("file_", "").replace("_", "/")
                            # Only process if it looks like a valid path
                            if not file_path.startswith("/"):
                                continue
                        
                        file_key_to_path[file_key] = file_path
                
                # Restore file content và permissions
                for file_key, file_path in file_key_to_path.items():
                    try:
                        file_content = backup.get("data", {}).get(file_key, "")
                        if not file_content:
                            print(f"   ⚠️ No content found for {file_path}, skipping")
                            continue
                        
                        print(f"🔄 Restoring {file_path}...")
                        
                        # Step 1: Restore file content
                        restore_content_script = f"""
cat > /tmp/restore_{file_path.replace("/", "_")} << 'RESTORE_EOF'
{file_content}
RESTORE_EOF
cp /tmp/restore_{file_path.replace("/", "_")} {file_path}
rm /tmp/restore_{file_path.replace("/", "_")}
"""
                        result_content = run_bash_check_stdin(
                            ssh, restore_content_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                        )
                        
                        if result_content["exit_status"] != 0:
                            print(f"   ⚠️ Failed to restore file content for {file_path}: {result_content.get('stderr', '')}")
                            rollback_details[file_path] = {
                                "status": "FAILED",
                                "error": result_content.get("stderr", ""),
                                "message": f"Failed to restore file content for {file_path}"
                            }
                            continue
                        
                        print(f"   ✓ File content restored for {file_path}")
                        
                        # Step 2: Restore permissions and ownership
                        perms_key = f"perms_{file_key.replace('file_', '')}"
                        perms_data = backup.get("data", {}).get(perms_key, "")
                        
                        if perms_data and perms_data != "unknown":
                            # Parse permissions (format: "644 root:root" or "600 0:0")
                            parts = perms_data.split()
                            if len(parts) >= 2:
                                perms = parts[0]  # e.g., "644", "600"
                                owner_group = parts[1]  # e.g., "root:root", "0:0"
                                
                                # Parse owner:group
                                if ":" in owner_group:
                                    owner, group = owner_group.split(":", 1)
                                else:
                                    owner = owner_group
                                    group = owner_group
                                
                                # Restore permissions and ownership
                                restore_perm_script = f"""
                                if [ -f {file_path} ]; then
                                    chmod {perms} {file_path}
                                    chown {owner}:{group} {file_path}
                                    echo "Permissions restored: {perms} {owner}:{group}"
                                else
                                    echo "File not found: {file_path}"
                                fi
                                """
                                result_perms = run_bash_check_stdin(
                                    ssh, restore_perm_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                                )
                                
                                if result_perms["exit_status"] == 0:
                                    rollback_details[file_path] = {
                                        "status": "RESTORED",
                                        "content_restored": True,
                                        "permissions": perms,
                                        "owner": owner,
                                        "group": group,
                                        "message": f"File content and permissions restored: {perms} {owner}:{group}"
                                    }
                                    print(f"   ✓ Permissions restored for {file_path}: {perms} {owner}:{group}")
                                else:
                                    rollback_details[file_path] = {
                                        "status": "PARTIAL",
                                        "content_restored": True,
                                        "permissions_restored": False,
                                        "error": result_perms.get("stderr", ""),
                                        "message": f"File content restored but permissions restore failed"
                                    }
                                    print(f"   ⚠️ File content restored but permissions restore failed for {file_path}")
                            else:
                                # Content restored but no permissions data
                                rollback_details[file_path] = {
                                    "status": "PARTIAL",
                                    "content_restored": True,
                                    "permissions_restored": False,
                                    "message": f"File content restored but no permissions data in backup"
                                }
                                print(f"   ⚠️ File content restored but no permissions data for {file_path}")
                        else:
                            # Content restored but no permissions in backup
                            rollback_details[file_path] = {
                                "status": "PARTIAL",
                                "content_restored": True,
                                "permissions_restored": False,
                                "message": f"File content restored but no permissions data in backup"
                            }
                            print(f"   ⚠️ File content restored but no permissions data for {file_path}")
                            
                    except Exception as e:
                        print(f"   ⚠️ Error restoring {file_path}: {e}")
                        import traceback
                        traceback.print_exc()
                        rollback_details[file_path] = {
                            "status": "ERROR",
                            "error": str(e),
                            "message": f"Error restoring {file_path}: {e}"
                        }
                
                # 3. Khôi phục sysctl settings (nếu có trong backup)
                if "sysctl_runtime" in backup.get("data", {}) or "file_etc_sysctl_conf" in backup.get("data", {}):
                    try:
                        print("🔄 Restoring sysctl settings...")
                        
                        # Restore /etc/sysctl.conf nếu có
                        sysctl_conf_key = None
                        if "file_etc_sysctl_conf" in backup.get("data", {}):
                            sysctl_conf_key = "file_etc_sysctl_conf"
                        elif "sysctl_conf" in backup.get("data", {}):
                            sysctl_conf_key = "sysctl_conf"
                        
                        if sysctl_conf_key:
                            sysctl_content = backup["data"][sysctl_conf_key]
                            restore_sysctl_script = f"""
                            cat > /tmp/sysctl_restore << 'SYSCTL_EOF'
                            {sysctl_content}
                            SYSCTL_EOF
                            cp /tmp/sysctl_restore /etc/sysctl.conf
                            rm /tmp/sysctl_restore
                            sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true
                            """
                            result = run_bash_check_stdin(
                                ssh, restore_sysctl_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result["exit_status"] == 0:
                                rollback_details["/etc/sysctl.conf"] = {
                                    "status": "RESTORED",
                                    "message": "Sysctl configuration restored"
                                }
                                print("   ✓ Sysctl configuration restored")
                            else:
                                rollback_details["/etc/sysctl.conf"] = {
                                    "status": "FAILED",
                                    "error": result.get("stderr", ""),
                                    "message": "Failed to restore sysctl configuration"
                                }
                                print(f"   ⚠️ Failed to restore sysctl config: {result.get('stderr', '')}")
                    except Exception as e:
                        print(f"   ⚠️ Error restoring sysctl settings: {e}")
                        rollback_details["sysctl"] = {
                            "status": "ERROR",
                            "error": str(e),
                            "message": f"Error restoring sysctl: {e}"
                        }
                
                # 4. Khôi phục mount options (nếu có trong backup)
                if "mount_info" in backup.get("data", {}):
                    try:
                        print("🔄 Restoring mount options...")
                        # Mount info is informational - actual mount options are in /etc/fstab
                        # If /etc/fstab was restored, mounts will be correct on next reboot
                        # For immediate effect, we could remount, but that's risky
                        rollback_details["mounts"] = {
                            "status": "INFO",
                            "message": "Mount options will be restored on next reboot (fstab restored)"
                        }
                        print("   ℹ️ Mount options will be restored on next reboot")
                    except Exception as e:
                        print(f"   ⚠️ Error processing mount info: {e}")
                
                # 5. Khôi phục service status (nếu có trong backup)
                rule_id = backup.get("rule_id", "")
                for key in backup.get("data", {}).keys():
                    if key.endswith("_service_status") or key.endswith("_service_enabled"):
                        service_name = key.replace("_service_status", "").replace("_service_enabled", "")
                        try:
                            print(f"🔄 Restoring {service_name} service status...")
                            
                            original_status = backup.get("data", {}).get(f"{service_name}_service_status", "unknown")
                            original_enabled = backup.get("data", {}).get(f"{service_name}_service_enabled", "unknown")
                            
                            restore_service_script = ""
                            
                            # Restore enabled status
                            if original_enabled != "unknown":
                                if original_enabled == "enabled":
                                    restore_service_script += f"systemctl enable {service_name} 2>/dev/null || systemctl enable {service_name}d 2>/dev/null || true\n"
                                elif original_enabled == "disabled":
                                    restore_service_script += f"systemctl disable {service_name} 2>/dev/null || systemctl disable {service_name}d 2>/dev/null || true\n"
                            
                            # Restore active status
                            if original_status != "unknown":
                                if original_status == "active":
                                    restore_service_script += f"systemctl start {service_name} 2>/dev/null || systemctl start {service_name}d 2>/dev/null || true\n"
                                elif original_status == "inactive":
                                    restore_service_script += f"systemctl stop {service_name} 2>/dev/null || systemctl stop {service_name}d 2>/dev/null || true\n"
                            
                            if restore_service_script:
                                result = run_bash_check_stdin(
                                    ssh, restore_service_script, use_sudo=True, sudo_password=sudo_password, timeout=30
                                )
                                rollback_details[f"{service_name}_service"] = {
                                    "status": "RESTORED",
                                    "original_status": original_status,
                                    "original_enabled": original_enabled,
                                    "message": f"Service {service_name} status restored"
                                }
                                print(f"   ✓ {service_name} service status restored: {original_status}/{original_enabled}")
                        except Exception as e:
                            print(f"   ⚠️ Error restoring {service_name} service: {e}")
                            rollback_details[f"{service_name}_service"] = {
                                "status": "ERROR",
                                "error": str(e),
                                "message": f"Error restoring {service_name} service: {e}"
                            }
                
                # 6. Khôi phục packages (nếu có trong backup)
                for key in backup.get("data", {}).keys():
                    if key.endswith("_installed"):
                        package_name = key.replace("_installed", "")
                        try:
                            print(f"🔄 Restoring {package_name} package...")
                            
                            original_status = backup.get("data", {}).get(key, "not_installed")
                            
                            if "not_installed" not in original_status.lower():
                                # Package was installed, reinstall it
                                restore_pkg_script = f"""
                                export DEBIAN_FRONTEND=noninteractive
                                timeout 120 apt-get install -y {package_name} 2>&1 || true
                                """
                                result = run_bash_check_stdin(
                                    ssh, restore_pkg_script, use_sudo=True, sudo_password=sudo_password, timeout=180
                                )
                                rollback_details[f"{package_name}_package"] = {
                                    "status": "RESTORED" if result["exit_status"] == 0 else "PARTIAL",
                                    "message": f"Package {package_name} reinstallation attempted"
                                }
                                print(f"   ✓ {package_name} package reinstallation attempted")
                            else:
                                # Package was not installed, ensure it's removed
                                rollback_details[f"{package_name}_package"] = {
                                    "status": "SKIPPED",
                                    "message": f"Package {package_name} was not installed originally"
                                }
                                print(f"   ℹ️ {package_name} was not installed originally, skipping")
                        except Exception as e:
                            print(f"   ⚠️ Error restoring {package_name} package: {e}")
                            rollback_details[f"{package_name}_package"] = {
                                "status": "ERROR",
                                "error": str(e),
                                "message": f"Error restoring {package_name} package: {e}"
                            }
                
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

