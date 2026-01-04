"""Auto-sync and import security rules from external standards (e.g., SCAP/XCCDF).

This module allows importing rules without manually writing YAML by:
- Accepting a URL or uploaded file containing SCAP/XCCDF (e.g., from complianceascode/SSG).
- Parsing rule metadata (id, title, severity, description).
- Generating YAML rule list under `content/rules/auto/{os}/`.
- Marking remediation/check as manual so users can attach scripts later.
"""
import os
import yaml
import urllib.request
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
RULES_DIR = os.path.join(REPO_ROOT, "content", "rules")
AUTO_RULES_DIR = os.path.join(RULES_DIR, "auto")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _safe_decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="ignore")


def detect_format(text: str) -> str:
    """Very simple format detection."""
    lowered = text.lower()
    if "<benchmark" in lowered or "<rule " in lowered or "<rule>" in lowered:
        return "xccdf"
    if lowered.strip().startswith("---") or lowered.strip().startswith("- "):
        return "yaml"
    return "yaml"  # default fallback


def parse_xccdf(text: str, os_name: str, source: str, profile: str) -> List[Dict]:
    """Parse minimal metadata from XCCDF/XML and return internal rule dicts."""
    root = ET.fromstring(text)
    # Namespace-agnostic search
    rules_xml = root.findall(".//{*}Rule")
    parsed: List[Dict] = []

    for rule in rules_xml:
        original_id = rule.attrib.get("id", "").strip() or "unknown"
        title_node = rule.find("{*}title")
        desc_node = rule.find("{*}description")
        severity = rule.attrib.get("severity", "unknown")

        title = (title_node.text or "").strip() if title_node is not None else original_id
        description = (desc_node.text or "").strip() if desc_node is not None else ""

        # Normalize id to keep traceability but avoid collisions
        normalized_id = original_id.lower().replace(" ", "-")
        generated_id = f"{source}-{os_name}-{normalized_id}"

        parsed.append(
            {
                "id": generated_id,
                "source_id": original_id,
                "title": title or original_id,
                "severity": severity,
                "description": description,
                "benchmark": source,
                "profile": profile,
                "os": os_name,
                "source": source,
                "imported_via": "rule_sync_xccdf",
                "check": {
                    "type": "manual",
                    "note": "Imported from XCCDF - no automated check attached",
                },
                "remediation": {
                    "type": "manual",
                    "note": "No remediation script attached (user can add later)",
                },
            }
        )

    return parsed


def _dedupe_rules(rules: List[Dict]) -> List[Dict]:
    deduped: List[Dict] = []
    seen = set()
    for r in rules:
        rid = r.get("id") or r.get("source_id")
        if not rid:
            continue
        if rid in seen:
            continue
        seen.add(rid)
        deduped.append(r)
    return deduped


def sync_rules_from_raw(
    raw: bytes,
    os_name: str,
    source: str = "ssg",
    profile: str = "default",
    format_hint: Optional[str] = None,
) -> Tuple[str, int]:
    """Import rules from raw content and write YAML under content/rules/auto/{os}/.

    Returns:
        (output_path, total_rules)
    """
    if not raw:
        raise ValueError("No data provided for rule sync")

    text = _safe_decode(raw)
    fmt = format_hint or detect_format(text)

    if fmt == "xccdf":
        rules = parse_xccdf(text, os_name=os_name, source=source, profile=profile)
    elif fmt == "yaml":
        loaded = yaml.safe_load(text) or []
        if isinstance(loaded, dict):
            loaded = [loaded]
        rules = []
        for idx, rule in enumerate(loaded):
            if not isinstance(rule, dict):
                continue
            # Ensure an id exists
            if not rule.get("id"):
                rule["id"] = f"{source}-{os_name}-rule-{idx}"
            rule.setdefault("os", os_name)
            rule.setdefault("benchmark", source)
            rule.setdefault("profile", profile)
            rule.setdefault("source", source)
            rule.setdefault(
                "check",
                {"type": "manual", "note": "Imported rule - no automated check attached"},
            )
            rule.setdefault(
                "remediation",
                {"type": "manual", "note": "No remediation script attached"},
            )
            rules.append(rule)
    else:
        raise ValueError(f"Unsupported format detected: {fmt}")

    rules = _dedupe_rules(rules)

    target_dir = os.path.join(AUTO_RULES_DIR, os_name)
    _ensure_dir(target_dir)
    filename = f"{source}-{profile}.yaml".replace("/", "_")
    output_path = os.path.join(target_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(rules, f, allow_unicode=False, sort_keys=False)

    return output_path, len(rules)


def fetch_url(url: str) -> bytes:
    if not url.startswith(("http://", "https://")):
        raise ValueError("Only http/https URLs are allowed for rule sync")
    with urllib.request.urlopen(url) as resp:
        return resp.read()


def sync_rules(
    os_name: str,
    source: str = "ssg",
    profile: str = "default",
    url: Optional[str] = None,
    raw_file: Optional[bytes] = None,
    format_hint: Optional[str] = None,
) -> Tuple[str, int]:
    """Public helper to sync rules from URL or uploaded file."""
    if not url and not raw_file:
        raise ValueError("Provide either url or file for rule sync")

    raw_data = raw_file or fetch_url(url)
    return sync_rules_from_raw(
        raw_data, os_name=os_name, source=source, profile=profile, format_hint=format_hint
    )

