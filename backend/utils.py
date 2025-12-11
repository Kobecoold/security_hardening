"""Common utilities for security hardening audit engine."""
import os
import yaml
from typing import List, Dict, Optional

# Đường dẫn tới thư mục rule gốc (tương đối theo repo)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
RULES_DIR = os.path.join(REPO_ROOT, "content", "rules")
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts", "remediation")


def load_rules(os_type: Optional[str] = None) -> List[Dict]:
    """Đọc và parse tất cả file YAML trong thư mục Windows (windows-10 hoặc windows-11).
    
    Args:
        os_type: Loại OS (windows-10, windows-11). Nếu None, sẽ thử cả hai.
    """
    # Xác định thư mục Windows rules
    if os_type and os_type.startswith("windows"):
        windows_dirs = [os.path.join(RULES_DIR, os_type)]
    else:
        # Thử cả windows-10 và windows-11
        windows_dirs = [
            os.path.join(RULES_DIR, "windows-10"),
            os.path.join(RULES_DIR, "windows-11")
        ]
    
    rules: List[Dict] = []
    
    # Đệ quy tìm tất cả file .yaml/.yml trong các thư mục Windows
    for windows_dir in windows_dirs:
        if not os.path.exists(windows_dir):
            continue
        
        for root, dirs, files in os.walk(windows_dir):
            for entry in sorted(files):
                if not entry.lower().endswith((".yml", ".yaml")):
                    continue
                file_path = os.path.join(root, entry)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if data is None:
                            continue
                        if isinstance(data, list):
                            rules.extend(data)
                        elif isinstance(data, dict):
                            rules.append(data)
                except Exception as exc:
                    # Bỏ qua file hỏng nhưng ghi chú lỗi
                    print(f"Warning: Failed to load rules from {file_path}: {exc}")
                    continue
    
    if not rules:
        raise FileNotFoundError(f"No valid Windows rules found in {windows_dirs}")
    
    return rules


def load_rules_by_os(os_name: str) -> List[Dict]:
    """Nạp tất cả rule YAML theo thư mục hệ điều hành, ví dụ: ubuntu-22.04, debian-12.

    Hỗ trợ cấu trúc phẳng hoặc theo subfolder (kernel, ssh, network...).
    Trả về danh sách rule (mỗi rule là dict). Hỗ trợ cả file YAML trả về 1 rule hoặc danh sách rule.
    """
    os_dir = os.path.join(RULES_DIR, os_name)
    if not os.path.isdir(os_dir):
        raise FileNotFoundError(f"Rules directory not found for OS '{os_name}': {os_dir}")
    
    rules: List[Dict] = []
    
    # Đệ quy tìm tất cả file .yaml/.yml
    for root, dirs, files in os.walk(os_dir):
        for entry in sorted(files):
            if not entry.lower().endswith((".yml", ".yaml")):
                continue
            file_path = os.path.join(root, entry)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data is None:
                        continue
                    if isinstance(data, list):
                        rules.extend(data)
                    elif isinstance(data, dict):
                        rules.append(data)
            except Exception as exc:
                # Bỏ qua file hỏng nhưng ghi chú lỗi trong kết quả gọi API cấp trên
                from fastapi import HTTPException
                raise HTTPException(status_code=500, detail=f"Failed to load rules from {file_path}: {exc}")
    return rules


def filter_rules(
    rules: List[Dict],
    ids: Optional[List[str]] = None,
    level: Optional[str] = None,
    benchmark: Optional[str] = None,
) -> List[Dict]:
    """Lọc rules theo ids, level, hoặc benchmark."""
    filtered: List[Dict] = []
    ids_set = set(ids or [])
    for r in rules:
        if ids_set and r.get("id") not in ids_set:
            continue
        if level and str(r.get("level")) != str(level):
            continue
        if benchmark and r.get("benchmark") != benchmark:
            continue
        filtered.append(r)
    return filtered


def load_remediation_script(os_name: str, rule_id: str) -> Optional[str]:
    """Load remediation script từ file system theo rule_id."""
    script_path = os.path.join(SCRIPTS_DIR, os_name, f"{rule_id}.sh")
    if os.path.exists(script_path):
        with open(script_path, "r", encoding="utf-8") as f:
            return f.read()
    return None

def load_windows_remediation_script(script_name: str) -> Optional[str]:
    """Load Windows remediation script từ file system."""
    # Thử cả "window-10" và "windows-10" để tương thích
    possible_paths = [
        os.path.join(SCRIPTS_DIR, "window-10", script_name),  # Thư mục thực tế
        os.path.join(SCRIPTS_DIR, "windows-10", script_name),  # Fallback
    ]
    
    for script_path in possible_paths:
        if os.path.exists(script_path):
            try:
                with open(script_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                print(f"Warning: Failed to read script {script_path}: {e}")
                continue
    
    print(f"Error: Script not found: {script_name}. Tried paths: {possible_paths}")
    return None
