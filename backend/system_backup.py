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
        sudo_password: Optional[str] = None,
        backup_options: Optional[Dict] = None
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
                # Default backup options (all enabled)
                options = backup_options or {
                    "ssh_config": True,
                    "users_groups": True,
                    "network_config": True,
                    "security_config": True,
                    "system_services": True,
                    "firewall_config": True,
                    "logging_config": True,
                    "system_info": True,
                }
                
                # Important system files to backup for Linux
                important_files = []
                
                # SSH Configuration
                if options.get("ssh_config", True):
                    important_files.extend([
                        "/etc/ssh/sshd_config",
                        "/etc/ssh/ssh_config",
                    ])
                
                # User and Group Management
                if options.get("users_groups", True):
                    important_files.extend([
                        "/etc/passwd",
                        "/etc/group",
                        "/etc/shadow",  # With sudo only
                        "/etc/gshadow",  # With sudo only
                    ])
                
                # Network Configuration
                if options.get("network_config", True):
                    important_files.extend([
                        "/etc/hosts",
                        "/etc/hostname",
                        "/etc/resolv.conf",
                        "/etc/nsswitch.conf",
                        "/etc/network/interfaces",  # Debian/Ubuntu
                        "/etc/sysconfig/network-scripts/ifcfg-*",  # RHEL/CentOS
                        "/etc/netplan",  # Ubuntu 18.04+
                    ])
                
                # Security Configuration
                if options.get("security_config", True):
                    important_files.extend([
                        "/etc/sudoers",
                        "/etc/sudoers.d",  # Directory listing
                        "/etc/security/limits.conf",
                        "/etc/security/pwquality.conf",
                    ])
                
                # System Services
                if options.get("system_services", True):
                    important_files.extend([
                        "/etc/fstab",
                        "/etc/mtab",
                        "/etc/crontab",
                        "/etc/cron.d",  # Directory listing
                        "/etc/systemd/system",  # Directory listing
                    ])
                
                # Firewall Configuration
                if options.get("firewall_config", True):
                    important_files.extend([
                        "/etc/ufw/ufw.conf",  # Ubuntu
                        "/etc/firewalld/firewalld.conf",  # RHEL/CentOS
                        "/etc/iptables/rules.v4",  # iptables rules
                    ])
                
                # Logging Configuration
                if options.get("logging_config", True):
                    important_files.extend([
                        "/etc/rsyslog.conf",
                        "/etc/logrotate.conf",
                    ])
                
                for file_path in important_files:
                    try:
                        # Handle directories differently
                        if file_path.endswith('*') or '/etc/sudoers.d' in file_path or '/etc/cron.d' in file_path or '/etc/systemd/system' in file_path:
                            # List directory contents
                            dir_path = file_path.replace('/*', '').replace('*', '')
                            print(f"🔍 Backing up directory listing: {dir_path}...")
                            list_script = f"""
                            timeout 10 sh -c 'if [ -d {dir_path} ]; then ls -la {dir_path} 2>/dev/null | head -50; fi'
                            """
                            result = run_bash_check_stdin(ssh, list_script, use_sudo=False, timeout=15)
                            if result["exit_status"] == 0 and result["stdout"]:
                                dir_key = dir_path.replace("/", "_").replace(".", "_")
                                backup_data["data"][f"dir_listing_{dir_key}"] = result["stdout"][:10000]
                                print(f"   ✓ {dir_path} directory listing backed up")
                            continue
                        
                        print(f"🔍 Backing up {file_path}...")
                        # Use timeout and limit size (100KB per file)
                        backup_script = f"""
                        timeout 10 sh -c 'if [ -f {file_path} ]; then head -c 100000 {file_path}; fi'
                        """
                        result = run_bash_check_stdin(
                            ssh, backup_script, use_sudo=False, timeout=15
                        )
                        
                        if result["exit_status"] == 0 and result["stdout"]:
                            file_key = file_path.replace("/", "_").replace(".", "_")
                            backup_data["data"][f"file_{file_key}"] = result["stdout"][:100000]
                            print(f"   ✓ {file_path} backed up ({len(result['stdout'])} bytes)")
                        else:
                            # Try with sudo for protected files (shadow, sudoers, etc.)
                            result_sudo = run_bash_check_stdin(
                                ssh, backup_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result_sudo["exit_status"] == 0 and result_sudo["stdout"]:
                                file_key = file_path.replace("/", "_").replace(".", "_")
                                backup_data["data"][f"file_{file_key}"] = result_sudo["stdout"][:100000]
                                print(f"   ✓ {file_path} backed up with sudo ({len(result_sudo['stdout'])} bytes)")
                            else:
                                print(f"   ⚠️ Skipped {file_path} (not accessible)")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup {file_path}: {e}")
                
                # Backup system information
                if options.get("system_info", True):
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
        password: str,
        backup_options: Optional[Dict] = None
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
            
            # Default backup options (all enabled)
            options = backup_options or {
                "registry_keys": True,
                "security_policies": True,
                "firewall_rules": True,
                "system_info": True,
            }
            
            # Backup important Windows configurations
            try:
                # 1. Backup Registry (important keys for security)
                if options.get("registry_keys", True):
                    registry_keys = [
                        # Security Policies
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Security",
                        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Security",
                        
                        # Network Configuration
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry",
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
                        
                        # Firewall
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
                        
                        # User Rights
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                    ]
                    
                    for key in registry_keys:
                        try:
                            print(f"🔍 Backing up registry: {key}...")
                            result = session.run_cmd(f'reg query "{key}" /s')
                            if result.status_code == 0:
                                key_name = key.replace("\\", "_").replace(":", "_")
                                backup_data["data"][f"registry_{key_name}"] = result.std_out.decode()[:100000]
                                print(f"   ✓ {key} backed up")
                        except Exception as e:
                            print(f"   ⚠️ Failed to backup {key}: {e}")
                
                # 2. Backup Security Policies
                if options.get("security_policies", True):
                    try:
                        print("🔍 Backing up security policies...")
                        secpol_commands = [
                            'net accounts',
                            'net localgroup Administrators',
                            'secedit /export /cfg C:\\temp\\secpol.txt',
                        ]
                        security_data = {}
                        for cmd in secpol_commands:
                            try:
                                if 'secedit' in cmd:
                                    result = session.run_cmd(cmd)
                                    if result.status_code == 0:
                                        # Read the exported file
                                        read_result = session.run_cmd('type C:\\temp\\secpol.txt')
                                        if read_result.status_code == 0:
                                            security_data["secedit_export"] = read_result.std_out.decode()[:50000]
                                        # Clean up
                                        session.run_cmd('del C:\\temp\\secpol.txt')
                                else:
                                    result = session.run_cmd(cmd)
                                    if result.status_code == 0:
                                        cmd_name = cmd.replace(' ', '_').replace('/', '_')
                                        security_data[cmd_name] = result.std_out.decode()[:10000]
                            except Exception as e:
                                print(f"   ⚠️ Failed to run {cmd}: {e}")
                        
                        if security_data:
                            backup_data["data"]["security_policy"] = security_data
                            print("   ✓ Security policies backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup security policies: {e}")
                
                # 3. Backup Firewall Rules
                if options.get("firewall_rules", True):
                    try:
                        print("🔍 Backing up firewall rules...")
                        result = session.run_ps('Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Direction,Action | ConvertTo-Json')
                        if result.status_code == 0:
                            backup_data["data"]["firewall_rules"] = result.std_out.decode()[:50000]
                            print("   ✓ Firewall rules backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup firewall rules: {e}")
                
                # 4. Backup System Information
                if options.get("system_info", True):
                    try:
                        print("🔍 Backing up system information...")
                        sysinfo_script = """
                        systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Total Physical Memory"
                        wmic logicaldisk get size,freespace,caption
                        wmic service get name,displayname,startmode,state
                        """
                        result = session.run_cmd(sysinfo_script)
                        if result.status_code == 0:
                            backup_data["data"]["system_info"] = result.std_out.decode()[:20000]
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

