"""System Backup module - Independent system file backups."""
import paramiko
from datetime import datetime
from typing import Dict, Optional, List
from database import db
from linux_audit import ssh_connect, run_bash_check_stdin
from windows_audit import winrm_connect
import winrm


class SystemBackupManager:
    """Manages independent system backups (not tied to remediation)."""
    
    def __init__(self):
        self.db = db
    
    def create_linux_system_backup(
        self,
        host: str,
        username: str,
        key_path: str = "",
        password: Optional[str] = None,
        sudo_password: Optional[str] = None
    ) -> Optional[str]:
        """Create system backup for Linux - backup important system files."""
        try:
            print(f"🛡️ Creating system backup for Linux host: {host}")
            
            ssh = ssh_connect(host, username, key_path, password)
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "system_backup",
                "os_type": "linux",
                "backup_id": f"sys_backup_{int(datetime.utcnow().timestamp())}",
                "data": {}
            }
            
            try:
                # Important system files to backup
                important_files = [
                    "/etc/ssh/sshd_config",      # SSH configuration
                    "/etc/passwd",                # User accounts
                    "/etc/group",                 # Group information
                    "/etc/sudoers",               # Sudoers configuration (if readable)
                    "/etc/hosts",                 # Hosts file
                    "/etc/resolv.conf",          # DNS configuration
                    "/etc/fstab",                 # Filesystem table
                    "/etc/crontab",              # System crontab
                ]
                
                for file_path in important_files:
                    try:
                        print(f"🔍 Backing up {file_path}...")
                        # Use timeout and limit size
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
                            # Try with sudo for protected files
                            result_sudo = run_bash_check_stdin(
                                ssh, backup_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result_sudo["exit_status"] == 0 and result_sudo["stdout"]:
                                file_key = file_path.replace("/", "_").replace(".", "_")
                                backup_data["data"][f"file_{file_key}"] = result_sudo["stdout"][:50000]
                                print(f"   ✓ {file_path} backed up with sudo ({len(result_sudo['stdout'])} bytes)")
                            else:
                                print(f"   ⚠️ Skipped {file_path} (not accessible)")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup {file_path}: {e}")
                
                # Backup system information
                try:
                    print("🔍 Backing up system information...")
                    sysinfo_script = """
                    echo "=== System Info ==="
                    uname -a
                    echo "=== Disk Usage ==="
                    df -h | head -5
                    echo "=== Network Interfaces ==="
                    ip addr show | grep -E "^[0-9]+:|inet " | head -10
                    """
                    result = run_bash_check_stdin(ssh, sysinfo_script, use_sudo=False, timeout=15)
                    if result["exit_status"] == 0:
                        backup_data["data"]["system_info"] = result["stdout"][:10000]
                        print("   ✓ System info backed up")
                except Exception as e:
                    print(f"   ⚠️ Failed to backup system info: {e}")
                
                # Add backup metadata
                backup_data["data"]["backup_info"] = {
                    "backup_time": str(datetime.utcnow()),
                    "host": host,
                    "username": username,
                    "backup_type": "system_backup",
                    "scope": "Important system files and configurations"
                }
                
            finally:
                ssh.close()
            
            # Save to MongoDB
            backup_id = self._save_backup(backup_data)
            print(f"✅ System backup created for {host}: {backup_id}")
            
            return backup_id
            
        except Exception as e:
            print(f"❌ System backup creation failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def create_windows_system_backup(
        self,
        host: str,
        username: str,
        password: str
    ) -> Optional[str]:
        """Create system backup for Windows - backup important system configurations."""
        try:
            print(f"🛡️ Creating system backup for Windows host: {host}")
            
            session = winrm_connect(host, username, password)
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "system_backup",
                "os_type": "windows",
                "backup_id": f"sys_backup_{int(datetime.utcnow().timestamp())}",
                "data": {}
            }
            
            # Backup important Windows configurations
            try:
                # 1. Backup Registry (important keys)
                registry_keys = [
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
                ]
                
                for key in registry_keys:
                    try:
                        print(f"🔍 Backing up registry: {key}...")
                        result = session.run_cmd(f'reg query "{key}" /s')
                        if result.status_code == 0:
                            key_name = key.replace("\\", "_").replace(":", "_")
                            backup_data["data"][f"registry_{key_name}"] = result.std_out.decode()[:50000]
                            print(f"   ✓ {key} backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup {key}: {e}")
                
                # 2. Backup Security Policies
                try:
                    print("🔍 Backing up security policies...")
                    result = session.run_cmd('net accounts')
                    if result.status_code == 0:
                        backup_data["data"]["security_policy"] = result.std_out.decode()[:10000]
                        print("   ✓ Security policies backed up")
                except Exception as e:
                    print(f"   ⚠️ Failed to backup security policies: {e}")
                
                # 3. Backup System Information
                try:
                    print("🔍 Backing up system information...")
                    sysinfo_script = """
                    systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Type"
                    wmic logicaldisk get size,freespace,caption
                    """
                    result = session.run_ps(sysinfo_script)
                    if result.status_code == 0:
                        backup_data["data"]["system_info"] = result.std_out.decode()[:10000]
                        print("   ✓ System info backed up")
                except Exception as e:
                    print(f"   ⚠️ Failed to backup system info: {e}")
                
                # Add backup metadata
                backup_data["data"]["backup_info"] = {
                    "backup_time": str(datetime.utcnow()),
                    "host": host,
                    "username": username,
                    "backup_type": "system_backup",
                    "scope": "Important Windows system configurations and registry"
                }
                
            except Exception as e:
                print(f"⚠️ Error during backup: {e}")
            
            # Save to MongoDB
            backup_id = self._save_backup(backup_data)
            print(f"✅ System backup created for {host}: {backup_id}")
            
            return backup_id
            
        except Exception as e:
            print(f"❌ System backup creation failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _save_backup(self, backup_data: Dict) -> str:
        """Save backup to MongoDB."""
        try:
            result = self.db.backups.insert_one(backup_data)
            return str(result.inserted_id)
        except Exception as e:
            print(f"❌ Failed to save backup to MongoDB: {e}")
            return f"backup_error_{int(datetime.utcnow().timestamp())}"


system_backup_manager = SystemBackupManager()

