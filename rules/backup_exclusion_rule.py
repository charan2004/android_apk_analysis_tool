# =============================================================================
# rules/backup_exclusion_rule.py
# MASTG-BEST-0004 | MASTG-TEST-0262
# Category: STORAGE | Severity: HIGH
# =============================================================================

import os
import xml.etree.ElementTree as ET
from mastg_scanner.utils.xml_utils import get_attr
from mastg_scanner.utils.fs_utils import find_xml_resource


def _has_sensitive_exclusions(xml_path):
    """
    Parse a backup rules XML (backup_rules.xml or data_extraction_rules.xml)
    and check whether it contains meaningful exclusion entries.

    Returns True if any exclusion is found.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for elem in root.iter("exclude"):
            path_val = elem.attrib.get("path", "")
            cloud    = elem.attrib.get("cloud-backup")
            device   = elem.attrib.get("device-transfer")

            # Explicit cloud/device exclusion
            if cloud == "false" or device == "false":
                return True

            # Heuristic: common sensitive Android directories
            if any(
                seg in path_val.lower()
                for seg in ["shared_prefs", "databases", "files", "cache"]
            ):
                return True

        # data_extraction_rules.xml uses <exclude> inside <cloud-backup>
        # or <device-transfer> sections — check for any child exclusions
        for section in ["cloud-backup", "device-transfer"]:
            sec_elem = root.find(section)
            if sec_elem is not None and list(sec_elem):   # has children
                return True

    except Exception:
        return False

    return False


def run(context):
    """
    MASTG-BEST-0004 — Exclude Sensitive Data from Backups.

    Evaluation:
      - allowBackup=false → PASS immediately
      - allowBackup=true with a valid exclusion config → PASS
      - allowBackup=true without exclusion config → FAIL
    """
    application = context.get("application")
    res_dir     = context.get("res_dir")
    min_sdk     = context.get("min_sdk")      # already int or None

    allow_backup = get_attr(application, "allowBackup")

    # Backup explicitly disabled — safest option
    if allow_backup == "false":
        return (
            "PASS",
            'android:allowBackup="false" — backup disabled',
            "MEDIUM",
            "MASTG-BEST-0004",
            "STORAGE"
        )

    # ---------- Backup is enabled (explicit true or default) ----------
    full_backup     = get_attr(application, "fullBackupContent")
    data_extraction = get_attr(application, "dataExtractionRules")

    # Choose the correct config file based on minSdkVersion:
    # API 31+ uses dataExtractionRules; older uses fullBackupContent
    if min_sdk is not None and min_sdk >= 31:
        config_file = "data_extraction_rules.xml" if data_extraction else None
    else:
        config_file = "backup_rules.xml" if full_backup else None

    if not config_file:
        return (
            "FAIL",
            "Backup is enabled but no exclusion rules file is configured "
            "(fullBackupContent / dataExtractionRules attribute missing)",
            "HIGH",
            "MASTG-BEST-0004",
            "STORAGE"
        )

    # Resolve path against res/xml/
    rules_path = find_xml_resource(res_dir, "xml", config_file)

    if not rules_path:
        return (
            "FAIL",
            f"{config_file} referenced in manifest but not found in res/xml/",
            "HIGH",
            "MASTG-BEST-0004",
            "STORAGE"
        )

    if not _has_sensitive_exclusions(rules_path):
        return (
            "FAIL",
            f"{config_file} exists but does not exclude sensitive directories",
            "HIGH",
            "MASTG-BEST-0004",
            "STORAGE"
        )

    return (
        "PASS",
        f"Sensitive data excluded via {config_file}",
        "MEDIUM",
        "MASTG-BEST-0004",
        "STORAGE"
    )
