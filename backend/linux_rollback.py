"""Rollback module for Linux security hardening."""
import paramiko
from datetime import datetime
from typing import Dict, Optional, List, Any
from database import db
from linux_audit import ssh_connect, run_bash_check_stdin
from utils import load_remediation_script, SCRIPTS_DIR, load_rules
import re
import os


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
                "data": {},
                # Lưu map file_key -> file_path để restore không bị mất dấu chấm / thư mục .d
                "paths": {}
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
                            # Create consistent key: strip leading /, replace / and . with _
                            file_key = file_path.lstrip("/").replace("/", "_").replace(".", "_")
                            backup_data["data"][f"file_{file_key}"] = content
                            backup_data["paths"][f"file_{file_key}"] = file_path
                            print(f"   ✓ {file_path} backed up ({len(content)} bytes)")
                        else:
                            # Thử với sudo nếu cần
                            result_sudo = run_bash_check_stdin(
                                ssh, backup_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result_sudo["exit_status"] == 0 and result_sudo["stdout"]:
                                content = result_sudo["stdout"][:100000]
                                # Create consistent key: strip leading /, replace / and . with _
                                file_key = file_path.lstrip("/").replace("/", "_").replace(".", "_")
                                backup_data["data"][f"file_{file_key}"] = content
                                backup_data["paths"][f"file_{file_key}"] = file_path
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
                            # Create consistent key: strip leading /, replace / and . with _
                            file_key = file_path.lstrip("/").replace("/", "_").replace(".", "_")
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
    
    def create_backup_for_rules(
        self, 
        host: str, 
        username: str,
        key_path: str = "",
        password: Optional[str] = None,
        sudo_password: Optional[str] = None,
        rule_ids: Optional[List[str]] = None
    ) -> Optional[str]:
        """Tạo backup chung cho nhiều rules - merge tất cả files/settings cần backup."""
        if not rule_ids or len(rule_ids) == 0:
            return None
        
        try:
            print(f"🛡️ Starting batch backup for Linux host: {host} with {len(rule_ids)} rules")
            
            ssh = ssh_connect(host, username, key_path, password)
            
            # Collect tất cả files cần backup từ tất cả rules (merge, không trùng lặp)
            all_files_to_backup = set()
            for rule_id in rule_ids:
                if rule_id:
                    files = self._get_files_to_backup_for_rule(rule_id)
                    all_files_to_backup.update(files)
                    print(f"   📋 Rule {rule_id}: {len(files)} files")
            
            all_files_to_backup = list(all_files_to_backup)
            print(f"✅ Total unique files to backup: {len(all_files_to_backup)}")
            
            backup_data = {
                "host": host,
                "timestamp": datetime.utcnow(),
                "type": "pre_remediation_backup",
                "os_type": "linux",
                "backup_id": f"backup_{int(datetime.utcnow().timestamp())}",
                "rule_ids": rule_ids,  # Lưu danh sách rules
                "rule_id": None,  # Không có rule_id đơn lẻ
                "data": {},
                "paths": {}
            }
            
            try:
                # Backup các file (giống như create_backup nhưng cho nhiều rules)
                for file_path in all_files_to_backup:
                    try:
                        print(f"🔍 Backing up {file_path}...")
                        backup_script = f"""
                        timeout 10 sh -c 'if [ -f {file_path} ]; then head -c 100000 {file_path}; fi'
                        """
                        result = run_bash_check_stdin(
                            ssh, backup_script, use_sudo=False, timeout=15
                        )
                        
                        if result["exit_status"] == 0 and result["stdout"]:
                            content = result["stdout"][:100000]
                            file_key = file_path.lstrip("/").replace("/", "_").replace(".", "_")
                            backup_data["data"][f"file_{file_key}"] = content
                            backup_data["paths"][f"file_{file_key}"] = file_path
                            print(f"   ✓ {file_path} backed up ({len(content)} bytes)")
                        else:
                            result_sudo = run_bash_check_stdin(
                                ssh, backup_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result_sudo["exit_status"] == 0 and result_sudo["stdout"]:
                                content = result_sudo["stdout"][:100000]
                                file_key = file_path.lstrip("/").replace("/", "_").replace(".", "_")
                                backup_data["data"][f"file_{file_key}"] = content
                                backup_data["paths"][f"file_{file_key}"] = file_path
                                print(f"   ✓ {file_path} backed up with sudo ({len(content)} bytes)")
                            else:
                                print(f"   ⚠️ Skipped {file_path} (not accessible)")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup {file_path}: {e}")
                
                # Backup file permissions
                for file_path in all_files_to_backup:
                    try:
                        print(f"🔍 Backing up permissions for {file_path}...")
                        perm_script = f"""
                        timeout 5 sh -c 'if [ -e {file_path} ]; then stat -c "%a %U:%G" {file_path} 2>/dev/null || stat -f "%OLp %Su:%Sg" {file_path} 2>/dev/null || echo "unknown"; fi'
                        """
                        result = run_bash_check_stdin(ssh, perm_script, use_sudo=True, sudo_password=sudo_password, timeout=10)
                        if result["exit_status"] != 0 or not result["stdout"] or result["stdout"].strip() == "unknown":
                            result = run_bash_check_stdin(ssh, perm_script, use_sudo=False, timeout=10)
                        if result["exit_status"] == 0 and result["stdout"] and result["stdout"].strip() != "unknown":
                            file_key = file_path.lstrip("/").replace("/", "_").replace(".", "_")
                            backup_data["data"][f"perms_{file_key}"] = result["stdout"].strip()
                            print(f"   ✓ Permissions backed up for {file_path}: {result['stdout'].strip()}")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup permissions for {file_path}: {e}")
                
                # Backup sysctl settings nếu có rules liên quan
                if any(rule_id and any(x in rule_id for x in ['3.1.', '3.2.', '3.3.']) for rule_id in rule_ids):
                    try:
                        print("🔍 Backing up sysctl settings...")
                        if "/etc/sysctl.conf" not in all_files_to_backup:
                            all_files_to_backup.append("/etc/sysctl.conf")
                        
                        sysctl_script = """
                        timeout 10 sh -c 'sysctl -a 2>/dev/null | grep -E "^(net\.ipv4\.|net\.ipv6\.)" | head -50'
                        """
                        result = run_bash_check_stdin(ssh, sysctl_script, use_sudo=True, sudo_password=sudo_password, timeout=15)
                        if result["exit_status"] == 0 and result["stdout"]:
                            backup_data["data"]["sysctl_runtime"] = result["stdout"][:50000]
                            print(f"   ✓ Sysctl runtime values backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup sysctl settings: {e}")
                
                # Backup services nếu có rules liên quan
                if any(rule_id and any(x in rule_id for x in ['2.2.', '2.1.']) for rule_id in rule_ids):
                    try:
                        print("🔍 Backing up system services status...")
                        services_script = """
                        timeout 10 sh -c 'systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -E "\.service" | awk "{print \\$1}" | head -100'
                        """
                        result = run_bash_check_stdin(ssh, services_script, use_sudo=True, sudo_password=sudo_password, timeout=15)
                        if result["exit_status"] == 0 and result["stdout"]:
                            backup_data["data"]["enabled_services"] = result["stdout"][:50000]
                            print(f"   ✓ Enabled services backed up")
                    except Exception as e:
                        print(f"   ⚠️ Failed to backup services: {e}")
                
                # Backup info
                rule_count = len(rule_ids)
                if rule_count == 1:
                    backup_scope_msg = f"Backup for 1 rule: {rule_ids[0]}"
                    notes_msg = f"Backup created before remediation for 1 rule - Only files that will be modified"
                else:
                    backup_scope_msg = f"Backup for {rule_count} rules: {', '.join(rule_ids[:5])}{'...' if rule_count > 5 else ''}"
                    notes_msg = f"Backup created before remediation for {rule_count} rules - Only files that will be modified"
                
                backup_data["data"]["backup_info"] = {
                    "backup_time": str(datetime.utcnow()),
                    "host": host,
                    "username": username,
                    "rule_ids": rule_ids,
                    "rule_count": rule_count,
                    "notes": notes_msg,
                    "backup_scope": backup_scope_msg
                }
                
            finally:
                ssh.close()
            
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
    
    def _extract_files_from_script(self, script_content: str) -> List[str]:
        """Extract file paths từ remediation script bằng cách tìm các patterns phổ biến."""
        files = []
        if not script_content:
            return files
        
        # Patterns để tìm file paths trong bash script
        # Tìm các patterns như: /etc/..., /boot/..., chmod /path/to/file, chown /path/to/file, etc.
        patterns = [
            r'(?:chmod|chown|cp|mv|cat\s+>|echo\s+.*>>|sed\s+-i.*)\s+([/][^\s\";\']+)',  # Commands với absolute paths
            r'["\']([/][^"\']+)["\']',  # Quoted absolute paths
            r'CONFIG_FILE=["\']([/][^"\']+)["\']',  # CONFIG_FILE variable
            r'FILE=["\']([/][^"\']+)["\']',  # FILE variable
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, script_content)
            for match in matches:
                # Clean up path (remove trailing characters)
                path = match.strip().rstrip(';').rstrip(')').rstrip('}')
                if path.startswith('/') and os.path.basename(path):  # Valid absolute path
                    files.append(path)
        
        return list(set(files))  # Remove duplicates
    
    def _get_files_to_backup_for_rule(self, rule_id: Optional[str]) -> List[str]:
        """Xác định các file cần backup dựa vào rule_id và remediation script."""
        if not rule_id:
            # Fallback: backup SSH config nếu không có rule_id
            return ["/etc/ssh/sshd_config"]
        
        files_to_backup = []
        
        # Thử extract files từ rule YAML file (tương tự Windows)
        try:
            # Extract OS name từ rule_id (e.g., cis-ubuntu-20.04-1.4.1 -> ubuntu-20.04)
            os_name_match = re.search(r'cis-([^-]+-\d+\.\d+)', rule_id)
            if os_name_match:
                os_name = os_name_match.group(1)
                
                # Thử load rules từ YAML
                try:
                    from utils import load_rules_by_os
                    rules = load_rules_by_os(os_name)
                    rule_data = None
                    for r in rules:
                        if r.get("id") == rule_id:
                            rule_data = r
                            break
                    
                    if rule_data:
                        # Extract file paths từ check command
                        check_cmd = rule_data.get("check", {}).get("ssh", "")
                        # Parse file paths từ check command (ví dụ: stat, test, cat, etc.)
                        # Pattern: file paths thường là absolute paths (/etc/...)
                        file_patterns = [
                            r'([/\w\.\-]+\.conf)',  # .conf files
                            r'([/\w\.\-]+\.cfg)',   # .cfg files
                            r'([/\w\.\-]+/passwd)', # /etc/passwd
                            r'([/\w\.\-]+/fstab)',  # /etc/fstab
                            r'([/\w\.\-]+/sshd_config)', # /etc/ssh/sshd_config
                            r'([/\w\.\-]+/grub\.cfg)', # /boot/grub/grub.cfg
                            r'([/\w\.\-]+/motd)',   # /etc/motd
                            r'([/\w\.\-]+/issue)',  # /etc/issue
                        ]
                        for pattern in file_patterns:
                            matches = re.findall(pattern, check_cmd)
                            for match in matches:
                                if match.startswith('/') and match not in files_to_backup:
                                    files_to_backup.append(match)
                                    print(f"   📋 Rule {rule_id}: extracted file {match} from YAML")
                except Exception as e:
                    print(f"   ⚠️ Failed to extract files from rule YAML: {e}")
                
                # Thử extract files từ remediation script
                script_content = load_remediation_script(os_name, rule_id)
                if script_content:
                    script_files = self._extract_files_from_script(script_content)
                    for f in script_files:
                        if f not in files_to_backup:
                            files_to_backup.append(f)
                    print(f"   📝 Extracted {len(script_files)} files from remediation script")
        except Exception as e:
            print(f"   ⚠️ Failed to extract files from script: {e}")
        
        # Fallback: Pattern-based mapping cho các rules phổ biến
        # Rule về SSH (5.2.x, 5.3.x)
        if any(x in rule_id for x in ['5.2.', '5.3.']):
            if '/etc/ssh/sshd_config' not in files_to_backup:
                files_to_backup.append("/etc/ssh/sshd_config")
        
        # Rule về file system mounts (1.1.x)
        if '1.1.' in rule_id:
            if 'tmp' in rule_id.lower() or 'var/tmp' in rule_id.lower():
                if '/etc/fstab' not in files_to_backup:
                    files_to_backup.append("/etc/fstab")
            elif 'home' in rule_id.lower():
                if '/etc/fstab' not in files_to_backup:
                    files_to_backup.append("/etc/fstab")
        
        # Rule về file permissions (1.2.x, 1.3.x, 1.4.x, 1.7.x)
        if any(x in rule_id for x in ['1.2.', '1.3.', '1.4.', '1.7.']):
            # Bootloader
            if '1.4.1' in rule_id or 'bootloader' in rule_id.lower() or 'grub' in rule_id.lower():
                if '/boot/grub/grub.cfg' not in files_to_backup:
                    files_to_backup.append("/boot/grub/grub.cfg")
            # MOTD
            elif '1.7.1' in rule_id or 'motd' in rule_id.lower():
                if '/etc/motd' not in files_to_backup:
                    files_to_backup.append("/etc/motd")
            # Common system files
            elif 'passwd' in rule_id.lower():
                if '/etc/passwd' not in files_to_backup:
                    files_to_backup.append("/etc/passwd")
            elif 'group' in rule_id.lower():
                if '/etc/group' not in files_to_backup:
                    files_to_backup.append("/etc/group")
            elif 'shadow' in rule_id.lower():
                if '/etc/shadow' not in files_to_backup:
                    files_to_backup.append("/etc/shadow")
            elif 'gshadow' in rule_id.lower():
                if '/etc/gshadow' not in files_to_backup:
                    files_to_backup.append("/etc/gshadow")
            elif 'fstab' in rule_id.lower():
                if '/etc/fstab' not in files_to_backup:
                    files_to_backup.append("/etc/fstab")
            elif 'crontab' in rule_id.lower():
                if '/etc/crontab' not in files_to_backup:
                    files_to_backup.append("/etc/crontab")
            elif 'hosts' in rule_id.lower():
                if '/etc/hosts' not in files_to_backup:
                    files_to_backup.append("/etc/hosts")
            elif 'issue' in rule_id.lower():
                if '/etc/issue' not in files_to_backup:
                    files_to_backup.append("/etc/issue")
                if '/etc/issue.net' not in files_to_backup:
                    files_to_backup.append("/etc/issue.net")
        
        # Rule về network (3.x) - sửa sysctl
        if rule_id.startswith('cis-') and any(x in rule_id for x in ['3.1.', '3.2.', '3.3.', '3.4.', '3.5.']):
            if '/etc/sysctl.conf' not in files_to_backup:
                files_to_backup.append("/etc/sysctl.conf")
            if ('sshd' in rule_id.lower() or 'ssh' in rule_id.lower()) and '/etc/ssh/sshd_config' not in files_to_backup:
                files_to_backup.append("/etc/ssh/sshd_config")
        
        # Rule về logging (4.x)
        if rule_id.startswith('cis-') and '4.' in rule_id:
            if 'rsyslog' in rule_id.lower() and '/etc/rsyslog.conf' not in files_to_backup:
                files_to_backup.append("/etc/rsyslog.conf")
            elif 'logrotate' in rule_id.lower() and '/etc/logrotate.conf' not in files_to_backup:
                files_to_backup.append("/etc/logrotate.conf")
            elif 'audit' in rule_id.lower():
                # Audit rules có thể sửa /etc/audit/rules.d/
                if '/etc/audit/audit.rules' not in files_to_backup:
                    files_to_backup.append("/etc/audit/audit.rules")
        
        # Rule về access control (5.x)
        if rule_id.startswith('cis-') and '5.' in rule_id:
            if ('sshd' in rule_id.lower() or 'ssh' in rule_id.lower()) and '/etc/ssh/sshd_config' not in files_to_backup:
                files_to_backup.append("/etc/ssh/sshd_config")
            elif 'sudo' in rule_id.lower() and '/etc/sudoers' not in files_to_backup:
                files_to_backup.append("/etc/sudoers")
        
        # Nếu không tìm thấy file nào, backup SSH config (phổ biến nhất)
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
        backup_id: Optional[str] = None,
        rule_id: Optional[str] = None
    ) -> Dict:
        """Thực hiện rollback dựa trên backup - hỗ trợ cả single rule và batch backups."""
        try:
            # Tìm backup - hỗ trợ cả single rule và batch backups
            if backup_id:
                backup = self.db.backups.find_one({"backup_id": backup_id, "host": host})
            elif rule_id:
                # Tìm backup gần nhất cho rule này - hỗ trợ cả single và batch backups
                query = {
                    "host": host,
                    "type": "pre_remediation_backup",
                    "os_type": "linux",
                    "$or": [
                        {"rule_id": rule_id},  # Single rule backup
                        {"rule_ids": rule_id}  # Batch backup chứa rule này
                    ]
                }
                backup = self.db.backups.find_one(query, sort=[("timestamp", -1)])
            else:
                # Tìm backup gần nhất (bất kỳ rule nào)
                backup = self.db.backups.find_one(
                    {"host": host, "type": "pre_remediation_backup", "os_type": "linux"},
                    sort=[("timestamp", -1)]
                )
            
            if not backup:
                error_msg = f"No backup found for Linux host {host}"
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
                print(f"🔄 Starting batch rollback for Linux host {host}")
                print(f"   Backup ID: {backup.get('backup_id', 'unknown')}")
                print(f"   Rules in backup: {', '.join(backup_rule_ids[:3])}{'...' if len(backup_rule_ids) > 3 else ''}")
                print(f"   Total rules: {len(backup_rule_ids)}")
                if rule_id and rule_id not in backup_rule_ids:
                    print(f"   ⚠️ Warning: Requested rule {rule_id} not in backup rules list")
            else:
                print(f"🔄 Starting rollback for Linux host {host}")
                print(f"   Backup ID: {backup.get('backup_id', 'unknown')}")
                print(f"   Rule: {backup_rule_id or 'N/A'}")
            
            ssh = ssh_connect(host, username, key_path, password)
            rollback_details = {}
            verification_results = {}
            
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
                path_map = backup.get("paths", {})
                for file_key in backup.get("data", {}).keys():
                    if not file_key.startswith("file_") or file_key.startswith("file_etc_ssh_sshd_config"):
                        continue

                    # Prefer path map (new backups)
                    if file_key in path_map:
                        file_key_to_path[file_key] = path_map[file_key]
                        continue

                    # Fallback: heuristics for old backups (no paths map)
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
                    elif "etc_issue_net" in file_key:
                        file_path = "/etc/issue.net"
                    elif "etc_issue" in file_key:
                        file_path = "/etc/issue"
                    else:
                        # Reconstruct from key (best-effort); fix common .d directories
                        reconstructed = "/" + file_key.replace("file_", "").replace("_", "/")
                        reconstructed = reconstructed.replace("/pam/d/", "/pam.d/")
                        reconstructed = reconstructed.replace("/rsyslog/d/", "/rsyslog.d/")
                        reconstructed = reconstructed.replace("/sysctl/conf", "/sysctl.conf")
                        reconstructed = reconstructed.replace("/fstab", "/fstab")
                        reconstructed = reconstructed.replace("/crontab", "/crontab")
                        file_path = reconstructed
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
                        
                        # Verify file content was restored correctly
                        verify_content_script = f"""
                        if [ -f {file_path} ]; then
                            # Compare first 1000 chars to avoid huge outputs
                            head -c 1000 {file_path}
                        else
                            echo "ERROR:File not found"
                        fi
                        """
                        verify_result = run_bash_check_stdin(
                            ssh, verify_content_script, use_sudo=True, sudo_password=sudo_password, timeout=10
                        )
                        content_verified = False
                        if verify_result["exit_status"] == 0:
                            restored_content_preview = verify_result.get("stdout", "")[:1000]
                            original_content_preview = file_content[:1000]
                            # Compare first 1000 chars (or full content if shorter)
                            if restored_content_preview == original_content_preview:
                                content_verified = True
                            elif len(file_content) <= 1000 and restored_content_preview == file_content:
                                content_verified = True
                        
                        if content_verified:
                            print(f"   ✓ File content restored and verified for {file_path}")
                        else:
                            print(f"   ⚠️ File content restored but verification failed for {file_path}")
                        
                        # If fstab restored, try to remount /tmp and /var/tmp to apply restored options
                        if file_path == "/etc/fstab":
                            print("   🔄 Attempting remount /tmp and /var/tmp to apply restored fstab...")
                            remount_script = """
                            mount -o remount /tmp 2>/dev/null || true
                            mount -o remount /var/tmp 2>/dev/null || true
                            """
                            remount_result = run_bash_check_stdin(
                                ssh, remount_script, use_sudo=True, sudo_password=sudo_password, timeout=10
                            )
                            if "/etc/fstab" not in rollback_details:
                                rollback_details["/etc/fstab"] = {}
                            rollback_details["/etc/fstab"].update({
                                "remount_exit": remount_result.get("exit_status", 0),
                                "remount_stdout": remount_result.get("stdout", "")[:200],
                                "remount_stderr": remount_result.get("stderr", "")[:200],
                            })
                            print("   ℹ️ Remount attempted (check remount_exit/remount_stdout).")

                            # Nếu fstab không còn entry cho /tmp hoặc /var/tmp nhưng mount vẫn đang tồn tại, thử umount
                            restored_fstab = file_content
                            need_umount_tmp = "/tmp" not in restored_fstab
                            need_umount_vartmp = "/var/tmp" not in restored_fstab
                            if need_umount_tmp or need_umount_vartmp:
                                print("   🔄 Checking active mounts for /tmp and /var/tmp after fstab restore...")
                                umount_script = """
                                set -e
                                current_mounts="$(mount)"
                                if ! echo "$current_mounts" | grep -q " on /tmp "; then
                                  echo "tmp_not_mounted"
                                else
                                  echo "tmp_mounted"
                                  umount -l /tmp 2>/dev/null || true
                                fi
                                if ! echo "$current_mounts" | grep -q " on /var/tmp "; then
                                  echo "vartmp_not_mounted"
                                else
                                  echo "vartmp_mounted"
                                  umount -l /var/tmp 2>/dev/null || true
                                fi
                                """
                                umount_result = run_bash_check_stdin(
                                    ssh, umount_script, use_sudo=True, sudo_password=sudo_password, timeout=10
                                )
                                rollback_details["/etc/fstab"].update({
                                    "umount_exit": umount_result.get("exit_status", 0),
                                    "umount_stdout": umount_result.get("stdout", "")[:200],
                                    "umount_stderr": umount_result.get("stderr", "")[:200],
                                })
                                print("   ℹ️ Umount attempted for tmp/var/tmp if they were still mounted.")

                        # Step 2: Restore permissions and ownership
                        perms_key = f"perms_{file_key.replace('file_', '')}"
                        perms_data = backup.get("data", {}).get(perms_key, "")
                        
                        print(f"   🔍 Looking for permissions key: {perms_key}")
                        print(f"   🔍 Found permissions data: {perms_data if perms_data else 'NOT FOUND'}")
                        
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
                                
                                # Convert numeric IDs to names if needed (0 -> root)
                                # But keep as-is if it's already a name (root)
                                # chown can handle both numeric and name, but let's be explicit
                                chown_owner = owner
                                chown_group = group
                                
                                print(f"   🔄 Restoring permissions: {perms} {owner}:{group}")
                                
                                # Restore permissions and ownership with verification
                                # Use explicit chmod and chown, then verify
                                restore_perm_script = f"""
                                if [ -f {file_path} ]; then
                                    # Set permissions
                                    chmod {perms} {file_path} 2>&1 || echo "CHMOD_ERROR:$?"
                                    # Set ownership (chown can handle both numeric and name)
                                    chown {chown_owner}:{chown_group} {file_path} 2>&1 || echo "CHOWN_ERROR:$?"
                                    # Verify the change using numeric format for consistency
                                    current_perms=$(stat -c "%a %u %g" {file_path} 2>/dev/null)
                                    current_perms_names=$(stat -c "%a %U:%G" {file_path} 2>/dev/null)
                                    echo "VERIFY_NUMERIC:$current_perms"
                                    echo "VERIFY_NAMES:$current_perms_names"
                                else
                                    echo "ERROR:File not found: {file_path}"
                                fi
                                """
                                result_perms = run_bash_check_stdin(
                                    ssh, restore_perm_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                                )
                                
                                # Parse verification output
                                verify_output = result_perms.get("stdout", "")
                                verified_perms = None
                                verified_perms_names = None
                                
                                # Parse numeric format (e.g., "644 0 0")
                                if "VERIFY_NUMERIC:" in verify_output:
                                    verify_lines = [line for line in verify_output.split("\n") if "VERIFY_NUMERIC:" in line]
                                    if verify_lines:
                                        verified_perms = verify_lines[0].replace("VERIFY_NUMERIC:", "").strip()
                                
                                # Parse names format (e.g., "644 root:root")
                                if "VERIFY_NAMES:" in verify_output:
                                    verify_lines = [line for line in verify_output.split("\n") if "VERIFY_NAMES:" in line]
                                    if verify_lines:
                                        verified_perms_names = verify_lines[0].replace("VERIFY_NAMES:", "").strip()
                                
                                # Check for errors
                                has_chmod_error = "CHMOD_ERROR:" in verify_output
                                has_chown_error = "CHOWN_ERROR:" in verify_output
                                
                                if result_perms["exit_status"] == 0 and verified_perms:
                                    # Check if permissions match what we set
                                    # verified_perms format: "644 0 0" (numeric)
                                    # We need to check if the first part (permissions) matches
                                    verified_parts = verified_perms.split()
                                    if len(verified_parts) >= 1 and verified_parts[0] == perms:
                                        rollback_details[file_path] = {
                                            "status": "RESTORED",
                                            "content_restored": True,
                                            "content_verified": content_verified if 'content_verified' in locals() else True,
                                            "permissions": perms,
                                            "owner": owner,
                                            "group": group,
                                            "verified_perms": verified_perms,
                                            "message": f"File content and permissions restored: {perms} {owner}:{group} (verified: {verified_perms})"
                                        }
                                        print(f"   ✓ Permissions restored for {file_path}: {perms} {owner}:{group} (verified: {verified_perms})")
                                    else:
                                        rollback_details[file_path] = {
                                            "status": "PARTIAL",
                                            "content_restored": True,
                                            "content_verified": content_verified if 'content_verified' in locals() else True,
                                            "permissions_restored": False,
                                            "expected": f"{perms} {owner}:{group}",
                                            "actual": verified_perms,
                                            "error": "Permissions verification failed",
                                            "message": f"File content restored but permissions mismatch: expected {perms}, got {verified_perms}"
                                        }
                                        print(f"   ⚠️ Permissions restore verification failed for {file_path}: expected {perms}, got {verified_perms}")
                                else:
                                    rollback_details[file_path] = {
                                        "status": "PARTIAL",
                                        "content_restored": True,
                                        "content_verified": content_verified if 'content_verified' in locals() else True,
                                        "permissions_restored": False,
                                        "error": result_perms.get("stderr", ""),
                                        "stdout": result_perms.get("stdout", ""),
                                        "message": f"File content restored but permissions restore failed or could not verify"
                                    }
                                    print(f"   ⚠️ Failed to restore permissions for {file_path}: {result_perms.get('stderr', '')}")
                                    print(f"   ⚠️ stdout: {result_perms.get('stdout', '')}")
                            else:
                                # Content restored but no permissions data
                                rollback_details[file_path] = {
                                    "status": "PARTIAL",
                                    "content_restored": True,
                                    "content_verified": content_verified if 'content_verified' in locals() else True,
                                    "permissions_restored": False,
                                    "message": f"File content restored but no permissions data in backup"
                                }
                                print(f"   ⚠️ File content restored but no permissions data for {file_path}")
                        else:
                            # Content restored but no permissions in backup
                            rollback_details[file_path] = {
                                "status": "PARTIAL",
                                "content_restored": True,
                                "content_verified": content_verified if 'content_verified' in locals() else True,
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
                
                # Reload services và apply changes sau khi restore files (tương tự Windows gpupdate)
                files_restored = sum(1 for k, v in rollback_details.items() 
                                   if isinstance(v, dict) and v.get("status") in ["RESTORED", "PARTIAL"])
                if files_restored > 0:
                    try:
                        print("🔄 Reloading services and applying changes after file restoration...")
                        
                        # Reload systemd daemon nếu có file systemd được restore
                        systemd_files = [k for k in rollback_details.keys() if 'systemd' in k.lower() or '/etc/systemd' in k]
                        if systemd_files:
                            reload_daemon_script = "systemctl daemon-reload 2>/dev/null || true"
                            result = run_bash_check_stdin(
                                ssh, reload_daemon_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result["exit_status"] == 0:
                                print("   ✓ Systemd daemon reloaded")
                        
                        # Reload sysctl nếu có sysctl.conf được restore
                        if "/etc/sysctl.conf" in rollback_details:
                            sysctl_reload_script = "sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true"
                            result = run_bash_check_stdin(
                                ssh, sysctl_reload_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result["exit_status"] == 0:
                                print("   ✓ Sysctl settings reloaded")
                        
                        # Reload cron nếu có crontab được restore
                        if "/etc/crontab" in rollback_details:
                            cron_reload_script = "systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null || service cron restart 2>/dev/null || true"
                            result = run_bash_check_stdin(
                                ssh, cron_reload_script, use_sudo=True, sudo_password=sudo_password, timeout=15
                            )
                            if result["exit_status"] == 0:
                                print("   ✓ Cron service reloaded")
                        
                        # Reload fstab changes (mount -a để apply ngay, nhưng cẩn thận)
                        if "/etc/fstab" in rollback_details:
                            print("   ℹ️ /etc/fstab restored - mount changes will apply on next reboot or manual remount")
                        
                        print("   ✓ System changes applied")
                    except Exception as e:
                        print(f"   ⚠️ Failed to reload services (non-critical): {e}")
                
            finally:
                ssh.close()
            
            # 5. (Optional) Verify rule state after rollback
            target_rule_ids: List[str] = []
            if rule_id:
                target_rule_ids = [rule_id]
            elif backup.get("rule_ids"):
                target_rule_ids = backup.get("rule_ids", [])
            elif backup.get("rule_id"):
                target_rule_ids = [backup.get("rule_id")]

            try:
                if target_rule_ids:
                    print(f"🔍 Verifying rules after rollback: {target_rule_ids}")
                    # Load rules from known OS directories (best-effort)
                    rules_all = []
                    try:
                        from utils import load_rules_by_os
                        for os_dir in ["ubuntu-20.04", "ubuntu-22.04", "debian-12"]:
                            try:
                                rules_all.extend(load_rules_by_os(os_dir, include_auto=True))
                            except Exception:
                                continue
                    except Exception:
                        pass

                    for rid in target_rule_ids:
                        rule_data = next((r for r in rules_all if r.get("id") == rid), None)
                        if not rule_data:
                            verification_results[rid] = {"status": "UNKNOWN", "message": "Rule not found for verification"}
                            continue
                        check_cmd = rule_data.get("check", {}).get("bash")
                        if not check_cmd:
                            verification_results[rid] = {"status": "SKIPPED", "message": "No bash check defined"}
                            continue
                        verify = run_bash_check_stdin(
                            ssh, check_cmd, use_sudo=True, sudo_password=sudo_password, timeout=20
                        )
                        status = "PASS" if verify.get("exit_status") == 0 else "FAIL"
                        verification_results[rid] = {
                            "status": status,
                            "exit_status": verify.get("exit_status"),
                            "stdout": verify.get("stdout", "")[:300],
                            "stderr": verify.get("stderr", "")[:200],
                        }
                        print(f"   ✓ Rule {rid} verification after rollback: {status}")
            except Exception as e:
                print(f"⚠️ Verification after rollback failed: {e}")
                verification_results["error"] = str(e)

            # Lưu rollback log + optional verification
            rollback_log = {
                "host": host,
                "backup_id": backup.get("backup_id", "unknown"),
                "timestamp": datetime.utcnow(),
                "type": "rollback_executed",
                "os_type": "linux",
                "rollback_details": rollback_details,
                "verification": verification_results,
                "status": "SUCCESS" if all(d.get("status") in ["RESTORED", "SKIPPED"] for d in rollback_details.values()) else "PARTIAL"
            }
            
            self.db.backups.insert_one(rollback_log)
            self._update_remediation_status(host, "ROLLED_BACK")
            
            # Tính toán status dựa trên rollback_details
            success_count = sum(1 for detail in rollback_details.values() 
                              if isinstance(detail, dict) and detail.get("status") in ["RESTORED", "SKIPPED"])
            total_count = len([d for d in rollback_details.values() if isinstance(d, dict)])
            
            if total_count == 0:
                final_status = "SKIPPED"
                message = f"No files to restore for Linux host {host}"
            elif total_count > 0 and success_count == total_count:
                final_status = "SUCCESS"
                message = f"Rollback completed successfully for Linux host {host}"
            elif success_count > 0:
                final_status = "PARTIAL"
                message = f"Rollback partially completed for Linux host {host} ({success_count}/{total_count} operations succeeded)"
            else:
                final_status = "FAILED"
                message = f"Rollback failed for Linux host {host} (0/{total_count} operations succeeded)"
            
            # Xác định backup_type (tương tự Windows)
            backup_rule_id = backup.get("rule_id")
            backup_rule_ids = backup.get("rule_ids")
            is_batch_backup = backup_rule_ids is not None and len(backup_rule_ids) > 0
            backup_type = "batch" if is_batch_backup else "single"
            
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
                },
                "error": None if final_status == "SUCCESS" else ("ROLLBACK_EXECUTION_ERROR" if final_status == "FAILED" else None)
            }
            
        except Exception as e:
            error_msg = f"Rollback failed: {str(e)}"
            print(f"❌ Rollback failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                "status": "FAILED",
                "message": error_msg,
                "host": host,
                "rule_id": rule_id,
                "backup_id": None,
                "backup_type": None,
                "rollback_details": {},
                "summary": {
                    "total_operations": 0,
                    "successful_operations": 0,
                    "failed_operations": 0
                },
                "error": "ROLLBACK_EXECUTION_ERROR",
                "error_details": str(e)
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

